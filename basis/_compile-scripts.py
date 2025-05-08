#!/usr/bin/env python3
from datetime import datetime
import subprocess
import argparse
import sys
import os
import re

SOURCE_MATCH = re.compile(r'''^\s*source\s+["']*(.*\.bash)["']*\s*$''')
SOURCE_REPLACE = re.compile(r'(\${.+})')
DESC_MATCH = re.compile(r'\s*#DESC[: ]+(.+)\s*$')
REMOVE_MATCH = re.compile(r'\W#%remove\s*')

_FLAGS = argparse.Namespace()

def print_err(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr)


def expand_file(
        filename:str,
        _recurselevel:int=0
    )->dict:
    """expand_file expands a file by including 'sourced' components recursively

    It also does a little additional processing to enable clean and compliant output

    Args:
        filename (str): file to read and expand
        _recurselevel (int, optional): how many levels we've recursed; internal use only. Defaults to 0.

    Returns:
        dict: a dictionary of 
             'content' (an array of lines to be written) and 
             'desc' (a string containing the file description)
    """    

    file_lines = []
    with open(filename, mode='r') as f:
        file_lines = f.readlines()

    output_lines = []
    file_description = ''
    for line in file_lines:
        line = line.rstrip() # remove trailing whitespace, including trailing newline
    

        ### simple tests
        if (line.startswith('#!') or line.startswith('#%')) and _recurselevel > 0:
            ## Shebang lines and #% comments are preserved in top-level files
            ## but removed from included files
            continue

        if _FLAGS.clean > 1 and line.lstrip().startswith('#'):
            ## clean comment-only lines if --clean was passed twice
            if _FLAGS.clean > 1 and line.lstrip().startswith('#'):
                continue

        elif line.startswith('###FOOTER'):
            ## when a footer is declared, stop processing the file
            ## this can be useful for debugging code, since code below will be `source`d but not
            ## included in the compiled result
            break
        
        ## if simple tests don't match, do the more expensive regex searches
        ## it's a little inefficent to do all three regexes every time, but
        ## it's easier to maintain and shouldn't matter much for small files
        source_match = SOURCE_MATCH.search(line)
        desc_match = DESC_MATCH.search(line)
        remove_match = REMOVE_MATCH.search(line)

        if source_match:
            ## I'm sourcing a script, so I'll want to replace it with file contents
            source_file_name = SOURCE_REPLACE.sub('.', source_match.group(1))
            print_err(
                f'''line match:\n"""{line}"""''',
                f'''\n   {source_match.group(1)} => {source_file_name}''')
            output_lines.append("")
            if _FLAGS.clean == 0:
                ## unless we've asked for --clean, mark the replacement
                output_lines.append(f"#%include '{os.path.basename(source_file_name)}'")
            output_lines.extend(
                expand_file(source_file_name, _recurselevel=_recurselevel+1)['content']
            )

        elif desc_match:
            ## I see a comment like ``#DESC: description text`` and want to save it for
            ## later use in file descriptor and copyright block
            print_err(f'''found description line '{desc_match.group(1)}' in file''')
            if file_description:
                file_description += "; " + desc_match.group(1)
            else:
                file_description = desc_match.group(1)

        elif remove_match:
            ## just remove the line
            pass

        else:
            ## if the line isn't special in any way, just add it as-is to output
            output_lines.append(line)

    
    return {
        'content': output_lines,
        'desc': file_description
    }


license_body = """#     Copyright (C) YYYY  Darren P Meyer

#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU Affero General Public License as published
#     by the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.

#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU Affero General Public License for more details.

#     You should have received a copy of the GNU Affero General Public License
#     along with this program.  If not, see <https://www.gnu.org/licenses/>.
""".replace('YYYY', str(datetime.today().year))

ARGS = argparse.ArgumentParser(
    prog="Script Complier",
    description="Compiles scripts to deployable state; See README.md in 'basis'")
ARGS.add_argument('filename', nargs='*')
ARGS.add_argument(
    '--clean', action='count', default=0,
    help=r"Suppress comments with '#%' in them, twice to suppress all comment-only lines")
ARGS.parse_args(namespace=_FLAGS)
if _FLAGS.clean > 2:
    print_err("Can only provide --clean a maximum of 2 times")
    exit(1)


for file in _FLAGS.filename:
    destfilename = None
    if ':' in file:
        ## this is input:output spec form
        file, destfilename = file.split(':', maxsplit=2)
    else: 
        destfilename =  os.path.join(
        os.path.dirname(file), '..', os.path.basename(file).replace('-base.','.')
    ) 

    print_err(f'''FILE [{file}]''')
    destfilename = os.path.relpath(os.path.abspath(destfilename))
    print_err(f"will write output to '{destfilename}'")

    result = expand_file(file)
    outlines = result['content']
    description = result['desc']

    try:
        with open(destfilename, 'w') as outf:
            print("\n".join(outlines), file=outf)
            file_desc = description if description is not None else 'generated script'
            print(f"""###\n# {os.path.basename(destfilename)} - {file_desc}\n""" + license_body, file=outf )
    except FileNotFoundError as err:
        print_err(f"Could not find pathway to '{destfilename}': does '{os.path.dirname(destfilename)}' exist?")
    
    sha512_file = destfilename + '.sha512'
    try:
        with open(sha512_file, 'w') as shaf:
            out = subprocess.run(['sha512sum', destfilename], stdout=shaf)
        out.check_returncode()
    except subprocess.CalledProcessError as err:
        print_err("Unable to generate SHA-512 sum: " + str(err))
        if os.path.exists(sha512_file):
            os.unlink(sha512_file)
        exit(1)

    try:
        out = subprocess.run(['/opt/homebrew/bin/gpg', '--detach-sign', '-a', destfilename], capture_output=True)
        out.check_returncode()
    except subprocess.CalledProcessError as err:
        print_err("Unable to generate signature: " + str(err))
        exit(1)
