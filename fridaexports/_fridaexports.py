import frida

scr = """ 'use strict';
//rpc.exports.enumeratemodules = function() {
//	return Process.enumerateModulesSync();
//}
rpc.exports = {
	enumerateModules: function() {
		return Process.enumerateModulesSync();
	},
	enumerateExports: function(modulePaths) {
		return modulePaths.map(function (modulePath) {
			return Module.enumerateExportsSync(modulePath);
		});
	},
	enumerateRanges: function(protection) {
		return Process.enumerateRangesSync(protection);
	},
	enumerateModuleRanges: function(moduleName, protection) {
		return Module.enumerateRangesSync(moduleName, protection)
	},
	findBaseAddress: function(moduleName) {
		var address = Module.findBaseAddress(moduleName);
		return (address!== null) ? address.toString() : "0";
	},
	readbyteArray: function(address, size) {
		return Memory.readByteArray(ptr(address), size);
	},
	writeByteArray: function (address, data) {
		var base = ptr(address);
		for(var i = 0; i!== data.length; i++){
			Memory.writeU8(base.add(i), data[i]);
		}
	},
	readUtf8String: function(address, length){
		return Memory.readUtf8String(ptr(address), length);
	},
	writeUtf8String: function(address, string){
		Memory.writeUtf8String(ptr(address, string));
	},
	enumerateModuleExports: function (modulePath) {
		return Module.enumerateExportsSync(modulePath).filter(function (e) {
			return e.type == 'function';
		});
	}
};
"""

def on_message(message,data):
	print("[on_message] message:", message, "data:", data)

class Exports:
    def __init__(self, target):
        self.rdev = frida.get_usb_device()
        self.session = self.rdev.attach(target)
        self.script = self.session.create_script(scr)
        self.script.on("message", on_message)
        self.script.load()

    def enumerateModules(self, excludeprefex=None):
        for m in self.script.exports.enumerate_modules():
            if not excludeprefex:
                print(m['path'])
            elif type(excludeprefex) == str:
                if not m["path"].startswith(excludeprefex):
                    print(m["path"])
            else:
                shouldexclude = False
                for prefex in excludeprefex:
                    if m["path"].startswith(prefex):
                        shouldexclude = True
                        break
                if shouldexclude:
                    continue
                print(m['path'])

    def enumerateExports(self, maps):
        return self.script.exports.enumerate_exports(maps)

    def enumerateRanges(self, protection):
        return self.script.exports.enumerate_ranges(protection)

    def enumerateModuleRanges(self, modulesName, protection):
        return self.script.exports.enumerate_module_ranges(modulesName, protection)

    def Test(self):
        #TestenumerateModules
        print("Test enumerateModules")
        self.enumerateModules()
        print("****************")
        self.enumerateModules("/system/lib")
        print("-----------------\n")

        print("Test enumerateExports")
        res = self.enumerateExports(["libgsl.so", "libinet.20170901.so"])
        print(len(res))
        for es in res:
            print(es)
        print("-------------------\n")

        print("Test enumerateRanges")
        outputResults(self.enumerateRanges("r-x"))
        #print("--------------------\n")

        print("Test enumerateModuleRanges")
        outputResults(self.enumerateModuleRanges("libinet.20170901.so", "---"))

def _outputtarget(results, i=0):
    if type(results) == list:
            print("  "*i + "[")
            for result in results:
                    _outputtarget(result, i+1)
            print("  "*i + "]")
    else:
            print("  "*i + str(results))

def outputResults(results):
    print("**********************")
    _outputtarget(results)
    print("------------------------\n")


