import clipboard
import idaapi
import sark

def callback():
	try:
		rva = clipboard.paste()
		jumpAddr = idaapi.get_imagebase() + int(rva, 16)
		print("[IDAssist.jumpToImageOffset]: Moving screen to: '{:02X}'.".format(jumpAddr))
		idaapi.jumpto(jumpAddr)
	except:
		print("[IDAssist.jumpToImageOffset]: Failed to jump.")


hotkeys = []

def load():
	hotkeys.append(idaapi.add_hotkey("Ctrl+Alt+R", callback))

def unload():
	for hotkey in hotkeys:
		idaapi.del_hotkey(hotkey)
