from importlib import reload
import tools.copy as copy
import tools.pattern as pattern
import tools.jumpToModuleOffset as jumpToModuleOffset

def load():
	print("loading IDAssist!")
	reload(copy).load()
	reload(pattern).load()
	reload(jumpToModuleOffset).load()

def unload():
	print("unloading IDAssist!")
	copy.unload()
	pattern.unload()
	jumpToModuleOffset.unload()