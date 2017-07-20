from os  import path, chdir
from sys import argv


chdir(path.dirname(path.abspath(argv[0])))
cph_help   = open('../CPH_Help.py', 'r')
cph_config = open('../CPH_Config.py', 'r')
cph_main   = open('../CustomParamHandler.py', 'r')


def write_imports(opened_file):
    line = opened_file.readline()
    while line:
        if line.strip() == 'from CPH_Config  import MainTab' \
        or line.strip() == 'from CPH_Help import CPH_Help':
            line = opened_file.readline()
            continue
        merged_file.write(line)
        if line.strip().startswith('#  End') and line.strip().endswith('Imports'):
            merged_file.write(opened_file.readline())
            merged_file.write('\n')
            break
        line = opened_file.readline()

with open('../CustomParamHandler_merged.py', 'w') as merged_file:
    write_imports(cph_help)
    write_imports(cph_config)
    write_imports(cph_main)

    for line in cph_help.readlines():
        merged_file.write(line)
    for line in cph_config.readlines():
        merged_file.write(line)
    for line in cph_main.readlines():
        merged_file.write(line)


cph_help  .close()
cph_config.close()
cph_main  .close()

