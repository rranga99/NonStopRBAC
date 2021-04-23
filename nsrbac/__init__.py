from nsrbac.safeguard import *
from nsrbac.nsutils import *
import csv
from filelock import *


def validate_user(subsystem, res, perm):
    """
    Validates whether the caller has:
    -	Access to the Subsystem
    -	Has a role with relevant permissions for a resource
    -	It returns False if the above conditions are not met with Authorization Error
    -   All input values are converted to Uppercase before validation.

    :param subsystem: Name of the subsystem for which access is needed
    :param res: Resource for which access is needed
    :param perm: Permissions to be checked for the resource
    :return: True/False
    """

    safe_guard = Safeguard()
    current_user = execute_in_oss_stderr("/bin/id -u -nr")[0].strip('\n')
    groups = safe_guard.get_user_groups(current_user)
    if path.exists("/usr/tandem/nsrbac/conf/roles_to_perm.csv"):
        if type(groups) is list:
            lockfile = "/usr/tandem/nsrbac/conf/roles_to_perm.csv"
            lock = FileLock(lockfile + ".lock")
            with lock:
                try:
                    with open("/usr/tandem/nsrbac/conf/roles_to_perm.csv", "r") as rperm:
                        csv_reader = csv.DictReader(rperm)
                        for row in csv_reader:
                            for group in groups:
                                if subsystem.upper() in group:
                                    print(row, group.upper(), res.upper(), perm.upper())
                                    if row["Rolename"] == group.upper() and \
                                            row["Resource"] == res.upper() and \
                                            row["Permission"] == perm.upper():
                                        return True
                except EnvironmentError or IOError:
                    return False
        else:
            return False
    else:
        return False
