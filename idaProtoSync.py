from idaapi import *
from idc import *
from idautils import *

import time
import json
import os


def ProtoSyncBuild(sigfile=None):
    print("Building ProtoSync signatures, this may take a few minutes...")
    start = time.time()

    if os.path.exists(sigfile):
        db = json.loads(open(sigfile).read())
    else:
        db = {}
    for func in Functions():
        tif = tinfo_t()
        get_tinfo2(func, tif)
        funcdata = func_type_data_t()
        tif.get_func_details(funcdata)
        funcdata.size()
        rettype = print_tinfo('', 0, 0, PRTYPE_1LINE, funcdata.rettype, '', '')
        if rettype is None:
            continue
        args = '('
        for i in xrange(funcdata.size()):
            arg_type = print_tinfo('', 0, 0, PRTYPE_1LINE, funcdata[i].type, '', '')
            arg_name = funcdata[i].name
            args += arg_type + ' ' + arg_name
            if i + 1 != funcdata.size():
                args += ', '
            else:
                args += ')'

        func_name = GetFunctionName(func)
        if func_name.startswith('.'):
            func_name = func_name[1:]
        db[func_name] = rettype + ' (__cdecl )' + args
        open(sigfile, 'w').write(json.dumps(db))

    end = time.time()
    print("Built signatures in %.2f seconds" % (end - start))


def ProtoSyncApply(sigfile=None):
    print("Applying ProtoSync signatures, this may take a few minutes...")
    start = time.time()

    db = json.loads(open(sigfile).read())
    for func in Functions():
        func_name = GetFunctionName(func)
        if func_name.startswith('.'):
            func_name = func_name[1:]
        if func_name in db:
            print('Update prototype for %s' % func_name)
            print('Set prototype: %s\n' % db.get(func_name))
            SetType(func, db.get(func_name).encode())

    end = time.time()
    print("Signatures applied in %.2f seconds" % (end - start))


class ProtoSyncPlugin(idaapi.plugin_t):
    flags = 0
    comment = "Function prototypes synchronize"
    help = "Identifies functions prototypes between two or more IDBs"
    wanted_name = "idaProtoSync"
    wanted_hotkey = ""

    def init(self):
        self.menu_context_load = idaapi.add_menu_item("File/Load file/", "ProtoSync signature file...", "", 0, self.sync_load, (None,))
        self.menu_context_produce = idaapi.add_menu_item("File/Produce file/", "ProtoSync signature file...", "", 0, self.sync_produce, (True,))
        return idaapi.PLUGIN_KEEP

    def term(self):
        idaapi.del_menu_item(self.menu_context_load)
        idaapi.del_menu_item(self.menu_context_produce)
        return None

    def run(self, arg):
        return None

    def sync_produce(self, arg):
        fname = AskFile(1, "*.sig", "Save signature file")
        if fname:
            if '.' not in fname:
                fname += ".sig"
            ProtoSyncBuild(fname)
        return None

    def sync_load(self, arg):
        fname = AskFile(0, "*.sig", "Load signature file")
        if fname:
            ProtoSyncApply(fname)
        return None


def PLUGIN_ENTRY():
    return ProtoSyncPlugin()
