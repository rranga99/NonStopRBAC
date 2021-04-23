from nsrbac.nsutils import *
from os import path


class Safeguard:

    def __init__(self):
        # 700 is the starting group for roles
        self.groupnum = 700

        if path.exists("/usr/tandem/nsrbac/conf/roles.csv"):
            try:
                with open("/usr/tandem/nsrbac/conf/roles.csv", "r") as role:
                    group_role = role.readlines()
                    self.groupnum = len(group_role) + 700 - 1
            except IOError or EnvironmentError:
                print("Error initializing Safeguard....")
                exit(1)

    def creategroup(self, rolename):
        command = "SAFECOM ADD GROUP {} , NUMBER {}, OWNER 255,255".format(rolename, self.groupnum)
        result = execute_in_tacl(command)
        if len(result) > 0:
            print(result)
            return 0
        else:
            return self.groupnum

    def add_user_to_role(self, rolename, user):
        command = "SAFECOM ALTER GROUP {} MEMBER {}".format(rolename, user)
        result = execute_in_tacl(command)
        if len(result) > 0:
            print(result)
            return False
        else:
            return True

    def get_user_groups(self, username):
        command = "SAFECOM INFO USER {}, DETAIL".format(username)
        result = execute_in_tacl(command)
        if "* ERROR *" in result:
            return FEERROR

        groups = [line for line in result if "GROUP         =" in line]
        group = []
        for line in groups:
            g_name = line.split('=')
            group.append(g_name[1].strip())
        return group
