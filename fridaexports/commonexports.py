import sys
import argparse
from _fridaexports import *

dsp='''
	#this py exports frida function
	#run frida-server on device and 
	adb forward tcp:27042 tcp:27042
	adb forward tcp:27043 tcp:27043
'''
if __name__ == '__main__':
	parser = argparse.ArgumentParser(description=dsp)
	parser.add_argument('--verbose', '-v', action='store_true', help='verbose mode', default=False)

	group = parser.add_mutually_exclusive_group()
	group.add_argument("-p", "--pid", type=int, help="the pid of target process")
	group.add_argument('-n', "--packagename", help="the packagename of target process")

	parser.add_argument("--version", action="version", version="%(prog)s 1.0")

	parser.add_argument("-E", "--Exports", action="append", help="execute enumerateExports [so1 so2 so3]")

	modulesgroup = parser.add_mutually_exclusive_group()

	modulesgroup.add_argument('-A', "--AllModules", action="store_true", default=False, help="list All Modules")
	modulesgroup.add_argument('-M', "--ModulesExclude", action="append", help="[startswith1 startswith2] list all modules exclude startswith subargs")

	#parser.add_argument()
	#parser.add_argument("packagename")

	args = parser.parse_args()
	if args.verbose:
		print("Verbose mode on!")
	#else:
	#	print("Verbose mode off!")

	try:
		
		exports=None 

		if args.pid:
			print("pid: " + args.pid)
			exports = Exports(args.pid)
		elif args.packagename:
			print("packagename: " + args.packagename)
			exports = Exports(args.packagename)
		else:
			print("[-p|n] must be set")
			exit()
		
		if args.AllModules:
			print("AllModules:")
			exports.enumerateModules()
			
		elif args.ModulesExclude:
			print("ModulesList:" + str(type(args.ModulesExclude)))
			exports.enumerateModules(args.ModulesExclude)

		if args.Exports:
			outputResults(exports.enumerateExports(args.Exports))
		
		

		
	except Exception, e:
		print(e)
		exit(1)

	





