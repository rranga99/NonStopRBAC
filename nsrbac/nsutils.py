"""This file includes the set of APIs that can be used to trigger nonstop specific functions."""
import subprocess

FEOK = True
FEERROR = False


def get_result_list(output):

    result_list = []

    result = output[0].split('\n'.encode())

    for string in result:
        if type(string) is str:
            result_list.append(string)
        else:
            result_list.append(string.decode())

    result_len = len(result_list)
    if result_len > 0 and result_list[result_len - 1] == '':
        result_list.pop()

    return result_list


def execute_in_tacl(command):
    process = subprocess.Popen(["gtacl", "-c", command], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    process.stdin.flush()

    return get_result_list(list(process.communicate()))


def execute_in_oss_stderr(command):
    process = subprocess.Popen(['/bin/sh', '-c', command], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
    process.stdin.flush()

    return get_result_list(list(process.communicate()))
