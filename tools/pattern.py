import idaapi
import ida_bytes
import clipboard

import sark

def callback():
	start, end = sark.core.fix_addresses()
	address, unk_1 = sark.get_selection()

	if not sark.Line().is_code:
		print("[IDAssist.pattern]: Address must be at the start of an instruction.")
		return

	print("[IDAssist.pattern]: Creating pattern for address: 0x{:02X}".format(address))

	data = bytes()
	mask = bytes()
	offset = 0
	success = 0

	for i in range(0, 100):
		line = sark.Line(address + offset)
		data += line.bytes
		insmask = [1 for x in range(0, line.size)]

		for op in line.insn.operands:
			if not op.type.is_reg and not op.type.is_phrase and not op.type.is_displ:
				for i in range(op._operand.offb, line.size):
					insmask[i] = 0
				break

		mask += bytes(insmask)
		
		if ida_bytes.bin_search(start, address, data, mask, ida_bytes.BIN_SEARCH_FORWARD, 0) == idaapi.BADADDR:
			if ida_bytes.bin_search(address + len(data), end, data, mask, ida_bytes.BIN_SEARCH_FORWARD, 0) == idaapi.BADADDR:
				success += 1
				break

		offset += line.size

	pattern = str()

	if success > 0:
		for i, byte in enumerate(data):
			if mask[i] == 1:
				success += 1
				pattern += "{:02X} ".format(byte)
			else:
				pattern += "? "

	if success < 2:
		print("[IDAssist.pattern]: Pattern maker failed! R:{}".format(success))
		return

	pattern = pattern.rstrip()
	clipboard.copy(pattern)
	print("[IDAssist.pattern]: copied '{}' to clipboard.".format(pattern))


hotkeys = []

def load():
	hotkeys.append(idaapi.add_hotkey("Ctrl+Alt+S", callback))

def unload():
	for hotkey in hotkeys:
		idaapi.del_hotkey(hotkey)
