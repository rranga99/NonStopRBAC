A Role Based Access Control for NonStop with NonStop Safeguard

#About

This project is create a CLI and an API for RBAC on NonStop.
This internally uses NonStop Safeguard.

#Configuring

nsrbac needs no configuration. 

#Running

`nsrbac <command> <sub-command>`

*command* is users, roles, permissions
*subcommand* depends on command
        is adduser for users
        is createrole, assignrole for roles
        is addperm, createperm for permissions

The API exposed is *validate_user*.
validate_user validates whether the current user is allowed access for
a resource and an operation.