from os  import path, chdir
from sys import exit


if __name__ != '__main__':
    exit('[-] CPH_Merger.py should be invoked directly, not imported!')

def is_comment_or_whitespace(line):
    line = line.strip()
    if not line or line.startswith('#'):
        return True
    return False

def write_imports(source_file, destination_file):
    line = source_file.readline()
    while line:
        if line.startswith('class'):
            source_file.seek(source_file.tell() - len(line))
            break
        if line.strip().startswith('from CPH_Help'  )\
        or line.strip().startswith('from CPH_Config')\
        or line.strip().startswith('from tinyweb'   )\
        or is_comment_or_whitespace(line):
            line = source_file.readline()
            continue
        destination_file.write(line)
        line = source_file.readline()

chdir(path.dirname(path.abspath(__file__)))

try:
    source_files = [
        open('../CPH_Config.py'        , 'rb'),
        open('../CPH_Help.py'          , 'rb'),
        open('../CustomParamHandler.py', 'rb'),
        open('../tinyweb.py'           , 'rb'),
    ]

    with open('../CustomParamHandler_merged.py', 'wb') as destination_file:
        for source_file in source_files:
            write_imports(source_file, destination_file)

        for source_file in source_files:
            for line in source_file.readlines():
                if not is_comment_or_whitespace(line):
                    destination_file.write(line)

finally:
    for source_file in source_files:
        if not source_file.closed:
            source_file.close()

