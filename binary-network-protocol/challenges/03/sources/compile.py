# Taken from https://gist.github.com/itdaniher/46fec3dd3b7eb603d7cbb5cd55fa5e1d

import subprocess
import sys
import tempfile
from Cython.Compiler import Main, CmdLine, Options

in_file_name = sys.argv[1]
source = open(in_file_name).read()
out_file_name = in_file_name.replace('.py', '')

temp_py_file = tempfile.NamedTemporaryFile(suffix='.py', delete=False)
temp_py_file.write(source.encode())
temp_py_file.flush()

Main.Options.embed = 'main'
res = Main.compile_single(temp_py_file.name, Main.CompilationOptions(), '')

gcc_cmd = 'gcc -fPIC -O2 %s -I/usr/include/python3.7 -L/usr/lib/python3.7 -lpython3.7m -o %s' % (res.c_file, out_file_name)

print(gcc_cmd)
assert 0 == subprocess.check_call(gcc_cmd.split(' '))
