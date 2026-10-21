import os
import pickle
import subprocess

import yaml


def shell(user):
    # ruleid: python.subprocess-shell-true
    subprocess.run("ls " + user, shell=True)
    # ruleid: python.subprocess-shell-true
    subprocess.Popen(f"ls {user}", shell=True)
    # ok: python.subprocess-shell-true
    subprocess.run(["ls", user])
    # ok: python.subprocess-shell-true
    subprocess.run("ls -l", shell=True)


def system(user):
    # ruleid: python.os-system-dynamic
    os.system("ping " + user)
    # ok: python.os-system-dynamic
    os.system("true")


def sql(cur, name, ident):
    # ruleid: python.sql-built-from-strings
    cur.execute("SELECT * FROM notes WHERE owner = '" + name + "'")
    # ruleid: python.sql-built-from-strings
    cur.execute(f"SELECT * FROM notes WHERE id = {ident}")
    # ruleid: python.sql-built-from-strings
    cur.execute("SELECT * FROM notes WHERE id = %s" % ident)
    # ruleid: python.sql-built-from-strings
    cur.execute("SELECT * FROM notes WHERE id = {}".format(ident))
    # ok: python.sql-built-from-strings
    cur.execute("SELECT * FROM notes WHERE id = ?", (ident,))
    # ok: python.sql-built-from-strings
    cur.execute("SELECT * FROM notes " + "ORDER BY id")


def dynamic(expr):
    # ruleid: python.eval-or-exec-dynamic
    eval(expr)
    # ruleid: python.eval-or-exec-dynamic
    exec(expr)
    # ok: python.eval-or-exec-dynamic
    eval("1 + 1")


def load(blob, text):
    # ruleid: python.unsafe-deserialization
    pickle.loads(blob)
    # ruleid: python.unsafe-deserialization
    yaml.load(text)
    # ok: python.unsafe-deserialization
    yaml.safe_load(text)
