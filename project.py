import idaapi

import importlib
import json
import mgr

def run():
	with open("<path to json file>") as file:

		try:
			data = json.loads(file.read())
		except ValueError as err:
			print("error parsing json:", err.args)
			return

		first = True

		print("#pragma once\n")
		print("namespace offsets\n{")

		for enumJson in data["enums"]:
			enum = mgr.Enum(enumJson)

			if not first:
				print("")  # add an empty line between enums

			first = False
			print(enum.cppstring)
			enum.definenames()

		print("}")


def callback():
	importlib.reload(mgr)
	run()


hotkeys = []

def load():
	print("[IDAssist.project]: Loaded!")
	hotkeys.append(idaapi.add_hotkey("Ctrl+Shift+A", callback))


def unload():
	for hotkey in hotkeys:
		idaapi.del_hotkey(hotkey)
