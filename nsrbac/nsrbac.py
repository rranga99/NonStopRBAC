"""
This file represents the most important functions done by the CLI.
"""
import click
from nsrbac.safeguard import *
from os import path, makedirs
import csv
import re
from filelock import *

safeguard = Safeguard()
all_roles = []
all_permissions = []
all_users = []
all_roles_to_user = []
all_roles_to_permission = []
all_resources = ["FILE", "PROCESS"]


def load_rbac_data():
    """

    :return: FEOK / FEERROR
    """
    global all_roles
    global all_users
    global all_permissions
    global all_roles_to_user
    global all_roles_to_permission

    if path.exists("/usr/tandem/nsrbac/conf/roles.csv"):
        lockfile = "/usr/tandem/nsrbac/conf/roles.csv"
        lock = FileLock(lockfile + ".lock")
        with lock:
            try:
                with open("/usr/tandem/nsrbac/conf/roles.csv", "r") as role:
                    group_roles = role.readlines()
                    for gr in group_roles:
                        grole = gr.split(',')
                        all_roles.append(grole[1].strip())
            except EnvironmentError or IOError:
                return FEERROR

    if path.exists("/usr/tandem/nsrbac/conf/permissions.csv"):
        lockfile = "/usr/tandem/nsrbac/conf/permissions.csv"
        lock = FileLock(lockfile + ".lock")
        with lock:
            try:
                with open("/usr/tandem/nsrbac/conf/permissions.csv", "r") as perm:
                    csv_reader = csv.DictReader(perm)
                    for row in csv_reader:
                        all_permissions.append(row['Permission'])
            except EnvironmentError or IOError:
                return FEERROR

    if path.exists("/usr/tandem/nsrbac/conf/users.csv"):
        lockfile = "/usr/tandem/nsrbac/conf/users.csv"
        lock = FileLock(lockfile + ".lock")
        with lock:
            try:
                with open("/usr/tandem/nsrbac/conf/users.csv", "r") as user:
                    csv_reader = csv.DictReader(user)
                    for row in csv_reader:
                        all_users.append(row['User'])
            except EnvironmentError or IOError:
                return FEERROR

    if path.exists("/usr/tandem/nsrbac/conf/roles_to_user.csv"):
        lockfile = "/usr/tandem/nsrbac/conf/roles_to_user.csv"
        lock = FileLock(lockfile + ".lock")
        with lock:
            try:
                with open("/usr/tandem/nsrbac/conf/roles_to_user.csv", "r") as ruser:
                    csv_reader = csv.DictReader(ruser)
                    for row in csv_reader:
                        fact = row['Rolename'] + "," + row['User']
                        all_roles_to_user.append(fact)
            except EnvironmentError or IOError:
                return FEERROR

    if path.exists("/usr/tandem/nsrbac/conf/roles_to_perm.csv"):
        lockfile = "/usr/tandem/nsrbac/conf/roles_to_perm..csv"
        lock = FileLock(lockfile + ".lock")
        with lock:
            try:
                with open("/usr/tandem/nsrbac/conf/roles_to_perm.csv", "r") as rperm:
                    csv_reader = csv.DictReader(rperm)
                    for row in csv_reader:
                        fact = row['Rolename'] + "," + row['Permission'] + "," + row['Resource']
                        all_roles_to_permission.append(fact)
            except EnvironmentError or IOError:
                return FEERROR

    return FEOK


@click.group()
def nsrbac():
    """nsrbac manages Role Based Access Control for NonStop"""
    current_user = (execute_in_oss_stderr("/bin/id -u -nr")[0].strip('\n')).upper()
    if "SUPER" not in current_user:
        groups = safeguard.get_user_groups(current_user)
        if "SUPER" not in groups:
            print("User {} not authorized to run this utility.".format(current_user))
            return FEERROR

    if load_rbac_data() == FEOK:
        create_initial_directory()


@nsrbac.group('users')
def users():
    """
    Commands for User management.
    Allows the administrator to allocate users to subsystem.
    """


@users.command('adduser')
@click.argument('gid_uid')
def add_user(gid_uid):
    """
    Add a new user to system. gid_uid is the groupid.userid
    of the user to be added. It should be in the format
    allowed by NonStop.
    """
    # Regex check
    # 1. Check if it begins with a character and length is 15 max.
    # 2. Should have a "." in between
    # 3. Should have at least one character after. Length is max 15.
    if (re.search('^[a-zA-Z]{1}[a-z0-9A-Z]{1,14}\.{1}[a-zA-Z]{1}[a-z0-9A-Z]{1,14}', gid_uid)) != None:
        # Add the user to local database
        if gid_uid not in all_users:
            saveuser(gid_uid.upper())
        else:
            print("User {} already defined".format(gid_uid.upper()))
    else:
        print(" Invalid user {}. Syntax Error".format(gid_uid.upper()))

@nsrbac.group('roles')
def roles():
    """
    Commands for Role management
    """


@roles.command('addrole')
@click.argument('rolename')
def add_role(rolename):
    """
    Add a role to RBAC.
    Its is of two parts. Subsystem name(max 15char) followed
    by a hyphen (-) then role name(max 15 character)
    """

    if rolename not in all_roles:
        # rolename must have two parts, let's check it
        if "-" not in rolename or \
                len(rolename) > 32:
            print("Invalid format/length for rolename. Specify <subsystem-name>-<rolename>.")
            return FEERROR
        else:
            groupnum = safeguard.creategroup(rolename.upper())
            if groupnum != 0:
                saverole(groupnum, rolename.upper())
    else:
        print("Role {} already defined.".format(rolename.upper()))


@roles.command('assignrole')
@click.argument('role')
@click.argument('user')
def assign_role(role, user):
    """
    Assign a role to a user.
    Role should be defined and available. user should be in the groupid.userid
    format allowed by NonStop. Stored in uppercase.
    """
    if (re.search('^[a-zA-Z]{1}[a-z0-9A-Z]{1,14}\.{1}[a-zA-Z]{1}[a-z0-9A-Z]{1,14}', user)) is None:
        print("Invalid user {}. Syntax Error.".format(user.upper()))
        return FEERROR

    if "-" not in role or \
            len(role) > 32:
        print("Invalid format/length for rolename. Specify <subsystem-name>-<rolename>.")
        return FEERROR

    fact = role.upper() + "," + user.upper()
    if fact in all_roles_to_user:
        print("The role {} is already assigned to user {}".format(role.upper(), user.upper()))
        return FEERROR

    if role.upper() not in all_roles or \
            user.upper() not in all_users:
        print("Either rolename or user is not defined.")
        return FEERROR

    fieldnames = ['Rolename', 'User']
    # Check whether the file exists
    if not path.exists("/usr/tandem/nsrbac/conf/roles_to_user.csv"):
        try:
            with open("/usr/tandem/nsrbac/conf/roles_to_user.csv", "w") as ruser:
                rpm_writer = csv.DictWriter(ruser, fieldnames=fieldnames)
                rpm_writer.writeheader()
                rpm_writer.writerow({'Rolename': role.upper(), 'User': user.upper()})
        except EnvironmentError or IOError:
            return FEERROR
    else:
        lockfile = "/usr/tandem/nsrbac/conf/roles_to_user.csv"
        lock = FileLock(lockfile + ".lock")
        with lock:
            try:
                with open("/usr/tandem/nsrbac/conf/roles_to_user.csv", "a") as ruser:
                    rpm_writer = csv.DictWriter(ruser, fieldnames=fieldnames)
                    rpm_writer.writerow({'Rolename': role.upper(), 'User': user.upper()})
            except EnvironmentError or IOError:
                return FEERROR

    if safeguard.add_user_to_role(role.upper(), user.upper()):
        print("Role {} is assigned to user {}".format(role.upper(), user.upper()))
    else:
        print("Unable to assign role {} to user {}".format(role.upper(), user.upper()))


@nsrbac.group('permissions')
def permissions():
    """
    Commands for Permissions management
    """


@permissions.command('createperm')
@click.argument('permname')
def create_permission(permname):
    """
    Creates a new permission in the system.
    PERMNAME is the name of the permission to add
    """
    if permname not in all_permissions:
        savepermission(permname.upper())
    else:
        print("Permission {} already defined.".format(permname.upper()))


@permissions.command('addperm')
@click.argument('permname')
@click.argument('rolename')
@click.argument('resource')
def add_permission_to_role_for_resource(permname, rolename, resource):
    """
    Adds a permission for a role to a resource.

    PERMNAME is the name of the permission to add
    ROLENAME is the role to add the permission to
    RESOURCE is the resource for which permission is added
    """
    if "-" not in rolename or \
            len(rolename) > 32:
        print("Invalid format/length for rolename. Specify <subsystem-name>-<rolename>.")
        return FEERROR

    if resource not in all_resources:
        print("Invalid resource. Specify FILE/PROCESS")
        return FEERROR

    fact = rolename.upper() + "," + permname.upper() + "," + resource.upper()
    if fact not in all_roles_to_permission:
        add_res_perm_to_role(permname.upper(), rolename.upper(), resource.upper())
    else:
        print("Role {} is already assigned permission {} for resource {}".format(rolename.upper(),
                                                                                 permname.upper(), resource.upper()))


def saveuser(gid_uid):
    """
    Saves the user to the local database
    This is loaded back when the CLI starts again
    :param gid_uid:
    :return: FEOK/FEERROR based on success/failure
    """

    fieldnames = ['User']
    # Check whether the file exists
    if not path.exists("/usr/tandem/nsrbac/conf/users.csv"):
        try:
            with open("/usr/tandem/nsrbac/conf/users.csv", "w") as user:
                user_writer = csv.DictWriter(user, fieldnames=fieldnames)
                user_writer.writeheader()
                user_writer.writerow({'User': gid_uid})
        except EnvironmentError or IOError:
            return FEERROR
        else:
            print("user {} is added".format(gid_uid))
    else:
        lockfile = "/usr/tandem/nsrbac/conf/users.csv"
        lock = FileLock(lockfile + ".lock")
        with lock:
            try:
                with open("/usr/tandem/nsrbac/conf/users.csv", "a") as user:
                    user_writer = csv.DictWriter(user, fieldnames=fieldnames)
                    user_writer.writerow({'User': gid_uid})
            except EnvironmentError or IOError:
                return FEERROR
            else:
                print("user {} is added".format(gid_uid))

    return FEOK


def saverole(groupnum, rolename):
    """
    Saves the role to the local database.
    :param rolename:
    :return:
    """
    fieldnames = ['Groupnum', 'Rolename']
    # Check whether the file exists
    if not path.exists("/usr/tandem/nsrbac/conf/roles.csv"):
        try:
            with open("/usr/tandem/nsrbac/conf/roles.csv", "w") as rgroup:
                rgp_writer = csv.DictWriter(rgroup, fieldnames=fieldnames)
                rgp_writer.writeheader()
                rgp_writer.writerow({'Groupnum': groupnum, 'Rolename': rolename})
        except EnvironmentError or IOError:
            return FEERROR
        else:
            print("Role {} is created with group {}".format(rolename, groupnum))
    else:
        lockfile = "/usr/tandem/nsrbac/conf/roles.csv"
        lock = FileLock(lockfile + ".lock")
        with lock:
            try:
                with open("/usr/tandem/nsrbac/conf/roles.csv", "a") as rgp:
                    rgp_writer = csv.DictWriter(rgp, fieldnames=fieldnames)
                    rgp_writer.writerow({'Groupnum': groupnum, 'Rolename': rolename})
            except EnvironmentError or IOError:
                return FEERROR
            else:
                print("Role {} is created with group {}".format(rolename, groupnum))

    return FEOK


def savepermission(permission):
    """

    :param permission: Type of permission
    :return: FEOK / FEERROR
    """
    if permission in all_permissions:
        print("Permission {} is already defined.".format(permission))
        return FEERROR

    fieldnames = ['Permission']
    # Check whether the file exists
    if not path.exists("/usr/tandem/nsrbac/conf/permissions.csv"):
        try:
            with open("/usr/tandem/nsrbac/conf/permissions.csv", "w") as perm:
                perm_writer = csv.DictWriter(perm, fieldnames=fieldnames)
                perm_writer.writeheader()
                perm_writer.writerow({'Permission': permission})
        except EnvironmentError or IOError:
            return FEERROR
        else:
            print("Permission {} is added".format(permission))
    else:
        lockfile = "/usr/tandem/nsrbac/conf/permissions.csv"
        lock = FileLock(lockfile + ".lock")
        with lock:
            try:
                with open("/usr/tandem/nsrbac/conf/permissions.csv", "a") as perm:
                    perm_writer = csv.DictWriter(perm, fieldnames=fieldnames)
                    perm_writer.writerow({'Permission': permission})
            except EnvironmentError or IOError:
                return FEERROR
            else:
                print("Permission {} is added".format(permission))
    return FEOK


def add_res_perm_to_role(permname, rolename, resource):
    """
    :param permname:
    :param rolename:
    :param resource:
    :return:
    """
    global all_roles
    global all_users
    global all_permissions

    if resource not in all_resources or \
            permname not in all_permissions or \
            rolename not in all_roles:
        print("Either rolename or permission or resource is not defined.")
        return FEERROR

    fieldnames = ['Rolename', 'Permission', 'Resource']

    # Check whether the file exists
    if not path.exists("/usr/tandem/nsrbac/conf/roles_to_perm.csv"):
        try:
            with open("/usr/tandem/nsrbac/conf/roles_to_perm.csv", "w") as rpm:
                rpm_writer = csv.DictWriter(rpm, fieldnames=fieldnames)
                rpm_writer.writeheader()
                rpm_writer.writerow({'Rolename': rolename, 'Permission': permname, 'Resource': resource})
        except EnvironmentError or IOError:
            return FEERROR
        else:
            print("Permission {} is assigned to role {} for resource {}".format(permname, rolename, resource))
    else:
        lockfile = "/usr/tandem/nsrbac/conf/roles_to_perm.csv"
        lock = FileLock(lockfile + ".lock")
        with lock:
            try:
                with open("/usr/tandem/nsrbac/conf/roles_to_perm.csv", "a") as rpm:
                    rpm_writer = csv.DictWriter(rpm, fieldnames=fieldnames)
                    rpm_writer.writerow({'Rolename': rolename, 'Permission': permname, 'Resource': resource})
            except EnvironmentError or IOError:
                return FEERROR
            else:
                print("Permission {} is assigned to role {} for resource {}".format(permname, rolename, resource))

    return FEOK


def create_initial_directory():
    """
    Creates the dirtectory for the local database where all the *.csv files
    are stored.
    :return:FEOK/FEERROR
    """
    if not path.exists("/usr/tandem/nsrbac/conf/"):
        try:
            makedirs("/usr/tandem/nsrbac/conf/")
        except OSError as e:
            print("Unable to create directory {}. Error {}".format("/usr/tandem/nsrbac/conf/", e))
            return FEERROR