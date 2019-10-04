from os  import path, chdir, SEEK_CUR
from sys import argv, platform


chdir(path.dirname(path.abspath(argv[0])))
cph_help   = open('../CPH_Help.py'          , 'r')
cph_config = open('../CPH_Config.py'        , 'r')
cph_main   = open('../CustomParamHandler.py', 'r')
tinyweb    = open('../tinyweb.py'           , 'r')


def write_imports(opened_file):
    line = opened_file.readline()
    while line:
        if line.startswith('class'):
            opened_file.seek(((len(line)+1)\
                    if "win" in platform.lower()\
                    else len(line))*-1, SEEK_CUR)
            merged_file.write('\n')
            break
        if line.strip().startswith('from CPH_Config')\
        or line.strip().startswith('from CPH_Help'  )\
        or line.strip().startswith('from tinyweb'   )\
        or line.strip().startswith('#'              )\
        or not line.strip():
            line = opened_file.readline()
            continue
        merged_file.write(line)
        line = opened_file.readline()

with open('../CustomParamHandler_merged.py', 'w') as merged_file:
    write_imports(cph_help)
    write_imports(tinyweb)
    write_imports(cph_config)
    write_imports(cph_main)

    for line in cph_help.readlines():
        merged_file.write(line)
    for line in tinyweb.readlines():
        merged_file.write(line)
    for line in cph_config.readlines():
        merged_file.write(line)
    for line in cph_main.readlines():
        merged_file.write(line)


cph_help  .close()
cph_config.close()
cph_main  .close()
tinyweb   .close()

