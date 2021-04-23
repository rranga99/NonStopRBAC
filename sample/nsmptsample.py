#!/usr/bin/env python

import nsmpt
import sys
import yaml
import nsrbac
from nsrbac import nsutils as ns


def main(yamlfile):
    '''
    This method is to invoke the nsmpt modules.
    input param:
        valid yaml file with required contents.
    Example:
        python nsmptsample.py acs_config_sample.yaml
    '''
    try:
        with open(yamlfile) as yaml_data:
            input_dict = yaml.safe_load(yaml_data)
            print(input_dict)
            yaml_data.close()

        current_user = ns.execute_in_oss_stderr("/bin/id -u -nr")[0].strip('\n')
        subsys = input_dict["action"].split("_")[0]
        if subsys == "acs":
            if "status" in input_dict["action"]:
                if not nsrbac.validate_user(subsys, "process", "read"):
                    raise Exception("User {} is not authorized for this operation.".format(current_user))
            elif "configure" in input_dict["action"]:
                if not (nsrbac.validate_user(subsys, "process", "create") and
                        nsrbac.validate_user(subsys, "file", "create")):
                    raise Exception("User {} is not authorized for this operation.".format(current_user))
        elif subsys == "pathmon":
            if "remove" in input_dict["action"]:
                if not (nsrbac.validate_user(subsys, "process", "stop") and
                        nsrbac.validate_user(subsys, "file", "delete")):
                    raise Exception("User {} is not authorized for this operation.".format(current_user))

        print('Performing action specified in the {}...'.format(yamlfile))

        output_dict = nsmpt.serve_request(input_dict)

        print(yaml.dump(output_dict, indent=4))

    except (ValueError, IOError) as e:
        print('invalid input yaml file: %s' % e)


if __name__ == '__main__':
    main(sys.argv[1])
