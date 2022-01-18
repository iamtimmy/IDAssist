import clipboard
import idaapi
import sark

def callback():
	start, end = sark.get_selection()
	copyValue = "0x{:02X}".format(start - idaapi.get_imagebase())
	clipboard.copy(copyValue)
	print("[IDAssist.copy]: Copied '{}' to clipboard.".format(copyValue))


hotkeys = []

def load():
	hotkeys.append(idaapi.add_hotkey("Ctrl+Shift+C", callback))

def unload():
	for hotkey in hotkeys:
		idaapi.del_hotkey(hotkey)
