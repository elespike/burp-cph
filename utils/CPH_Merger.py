from os  import path, chdir
from sys import argv


chdir(path.dirname(path.abspath(argv[0])))
cph_main = open('../CustomParamHandler.py', 'r')
cph_config = open('../CPH_Config.py', 'r')


def write_cph_imports():
    line = cph_main.readline()
    while line:
        if line.strip() == 'from CPH_Config import MainTab':
            line = cph_main.readline()
            continue
        merged_file.write(line)
        if line.strip() == '#  End CustomParameterHandler.py Imports':
            merged_file.write(cph_main.readline())
            merged_file.write('\n')
            break
        line = cph_main.readline()

def write_config_imports():
    line = cph_config.readline()
    while line:
        if line.strip() == 'from CPH_Help import CPH_Help':
            line = cph_config.readline()
            continue
        merged_file.write(line)
        if line.strip() == '#  End CPH_Config.py Imports':
            merged_file.write(cph_config.readline())
            merged_file.write('\n')
            break
        line = cph_config.readline()

with open('../CustomParamHandler_merged.py', 'w') as merged_file:
    write_cph_imports()
    write_config_imports()
    with open('../CPH_Help.py', 'r') as cph_help:
        merged_file.write(cph_help.read())
    for line in cph_config.readlines():
        merged_file.write(line)
    for line in cph_main.readlines():
        merged_file.write(line)


cph_main.close()
cph_config.close()

