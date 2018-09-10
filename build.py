import os, subprocess, shlex, sys, re, shutil, threading, time

# AMD 6376 is Piledriver march, use target-cpu=bdver2
# Xeon E5-2630 v4 is Broadwell march, use target-cpu=broadwell

CFLAGS  = "-ffreestanding -target x86_64 -march=native -O2 -fPIE \
           -g -ansi -pedantic -Wall -Werror -Isrcs -flto -Wno-long-long"
LDFLAGS = "-pie --lto-O2"

# Uncomment this line to make a debug friendly binary without optimizations and LTO
CFLAGS += " -fno-lto -O2"

OUTPUT_FILENAME       = "grilled_cheese.kern.debug"
OUTPUT_STRIP_FILENAME = "grilled_cheese.kern"
BOOTLOADER_FILENAME   = "grilled_cheese.boot"

printlock = threading.Lock()

def check_deps(out_file, deps):
    for dep in deps:
        # If the dependency was modified more recently than the output file
        try:
            if os.path.getmtime(dep) > os.path.getmtime(out_file):
                return True
        except:
            return True

    return False

# Returns true of infile is newer than outfile, or if outfile doesn't exist.
# Returns false otherwise.
def is_older(outfile, infile):
    if not os.path.exists(outfile) or os.path.getmtime(infile) > os.path.getmtime(outfile):
        return True
    else:
        return False

def get_cc_deps(in_c_fn):
    deps = []

    cmd = "clang %s -M %s" % (CFLAGS, in_c_fn)

    sp = subprocess.Popen(shlex.split(cmd, posix=False), stdout=subprocess.PIPE)
    stdout = sp.communicate()[0]
    if sp.wait() != 0:
        return None

    # We only care about the dependencies, split off the target
    stdout = stdout.split(b': ')[1]

    for include in stdout.split(b' '):
        if not include.startswith(b"srcs"):
            continue;

        deps.append(include.strip())

    return deps

def cc(in_c_fn, out_obj_fn):
    cmd = "clang %s -o %s -c %s" % (CFLAGS, out_obj_fn, in_c_fn)

    with printlock:
        print("CC    %s" % out_obj_fn)

    sp = subprocess.Popen(shlex.split(cmd, posix=False), stderr=subprocess.PIPE)
    stdout, stderr = sp.communicate()
    if sp.wait() != 0:
        with printlock:
            sp = subprocess.Popen(shlex.split(cmd, posix=False))
            sp.wait()

        sys.exit(-1)

    return

def asm(in_asm_fn, out_obj_fn):
    with printlock:
        print("ASM   %s" % in_asm_fn)

    cmd = "nasm -f elf64 -o %s %s" % (out_obj_fn, in_asm_fn)

    sp = subprocess.Popen(shlex.split(cmd, posix=False))
    if sp.wait() != 0:
        sys.exit(-1)

    return

def link(in_link_objs, out_fn):
    cmd = "ld.lld %s -o %s %s" % (LDFLAGS, out_fn, in_link_objs)

    with printlock:
        print("LD    %s" % out_fn)

    os.system(cmd)
    return

def strip(in_link_objs, out_fn):
    cmd = "ld.lld %s -strip-all -o %s %s" % (LDFLAGS, out_fn, in_link_objs)

    with printlock:
        print("STRIP %s" % out_fn)

    os.system(cmd)
    return

def buildfn(fn):
    if fn.find(' ') != -1:
        sys.stderr.write("Path \"%s\" contains a space\n" % fn)
        sys.exit(-1)

    obj = "objs" + fn[4:] + ".o"

    try:
        os.makedirs(os.path.split(obj)[0])
    except:
        pass

    if fn.endswith(".c"):
        deps = get_cc_deps(fn)
        if deps == None or check_deps(obj, deps):
            cc(fn, obj)
            built_objs.append(obj)
        else:
            skipped_objs.append(obj)
    elif fn.endswith(".asm"):
        if is_older(obj, fn):
            asm(fn, obj)
            built_objs.append(obj)
        else:
            skipped_objs.append(obj)
    else:
        sys.stderr.write("Unsupported file type \"%s\"\n" % fn)
        sys.exit(-1)

# Build every file with ext recursively in 'srcs' and place in 'objs'. Return
# space separated string of all output objects. Calls sys.exit(-1) on any
# error.
def build_all(ext):
    global built_objs, skipped_objs

    for cur, dirs, files in os.walk('srcs'):
        for fn in files:
            fn = os.path.join(cur, fn)

            if not fn.endswith(ext):
                continue

            threading.Timer(0.0, buildfn, args=[fn]).start()

    while threading.active_count() != 1:
        time.sleep(0.01)

if len(sys.argv) == 2 and sys.argv[1] == "clean":
    remove_dirs  = ["objs"]
    remove_files = [OUTPUT_FILENAME, OUTPUT_STRIP_FILENAME, BOOTLOADER_FILENAME]

    for rmdir in remove_dirs:
        print("RMDIR %s" % rmdir)
        if os.path.exists(rmdir):
            shutil.rmtree(rmdir)

    for rmfile in remove_files:
        print("RM    %s" % rmfile)
        if os.path.exists(rmfile):
            os.remove(rmfile)

    sys.exit(0)

built_objs   = []
skipped_objs = []

build_all(".c")
build_all(".asm")

if len(built_objs) or not os.path.exists(OUTPUT_FILENAME) or not os.path.exists(OUTPUT_STRIP_FILENAME):
    link(" ".join(built_objs + skipped_objs), OUTPUT_FILENAME)
    strip(" ".join(built_objs + skipped_objs), OUTPUT_STRIP_FILENAME)

if is_older(BOOTLOADER_FILENAME, os.path.join("bootloader", "grilled_cheese.asm")):
    print("ASM   %s" % BOOTLOADER_FILENAME)
    os.system("nasm -f bin -o %s bootloader/grilled_cheese.asm" % BOOTLOADER_FILENAME)

sys.exit(0)

