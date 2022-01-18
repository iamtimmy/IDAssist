from importlib import reload
import idaapi

import loader

class Plugin(idaapi.plugin_t):
	flags = 0
	comment = "reload IDAssist"
	help = ""
	wanted_name = "reload IDAssist"
	wanted_hotkey = "Ctrl+Shift+Alt+R"
	version = "0.0.2"

	def init(self):
		loader.load()
		return idaapi.PLUGIN_KEEP

	def run(self, arg):
		loader.unload()
		reload(loader).load()

	def term(self):
		loader.unload()

def PLUGIN_ENTRY():
	return Plugin()
