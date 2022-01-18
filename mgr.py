import idaapi
import sark

class Pattern:
	def __init__(self, json):
		if "pattern" not in json:
			raise ValueError(self, "invalid json entry: missing 'pattern'")

		if "method" not in json:
			raise ValueError(self, "invalid json entry: missing 'method'")

		self._pattern = json["pattern"]
		self._method = json["method"]
		self._searched = False
		self._address = 0

	@property
	def pattern(self):
		return self._pattern

	@property
	def method(self):
		return self._method

	@property
	def address(self):
		if not self._searched:
			for result in sark.core.iter_find_query(self.pattern):
				if result != idaapi.BADADDR:
					self._address = result

				break

			self._searched = True

		return self._address


class Entry:
	def __init__(self, json):
		if "name" not in json:
			raise ValueError(self, "invalid json entry: missing 'name'")

		self._name = json["name"]

		if "dontenum" in json:
			self._dontenum = json["dontenum"]
		else:
			self._dontenum = False

		if "patterns" in json:
			self._patterns = [Pattern(x) for x in json["patterns"]]
		else:
			self._patterns = []

		self._searched = False
		self._address = 0
		self._rebase = True

	@property
	def name(self):
		return self._name

	@property
	def patterns(self):
		return self._patterns

	@property
	def valid(self):
		return False

	@property
	def address(self):
		if not self._searched:
			for pattern in self.patterns:
				if pattern.address == 0:
					continue

				if self.scan(pattern.address, pattern.method):
					break

			self._searched = True

		return self._address

	@property
	def shouldenum(self):
		return self._dontenum == False

	@property
	def cppstring(self):
		if not self.shouldenum:
			return ""

		addr = self.address
		if self._rebase:
			addr = max(0, addr - idaapi.get_imagebase())

		if addr == 0:
			return "\t\t{} = 0x{:02X}, // Failed\n".format(self.name, 0)

		return "\t\t{} = 0x{:02X},\n".format(self.name, addr)

	def scan(self, address, method):
		return False

	def definename(self, enum_name):
		pass


class Address(Entry):
	@property
	def valid(self):
		if not self._address:
			return False

		# perhaps add some type of sanity checking?
		return True

	def scandirect(self, address):
		self._address = address
		return self.valid

	def scanretofreferencedfunc(self, address):
		line = sark.Line(address)

		if line.is_code:
			for operand in line.insn.operands:
				if operand.type.is_near:
					if sark.Function.is_function(operand.offset):
						endAddr = sark.Function(operand.offset).end_ea - 1

						if sark.Line(endAddr).insn.is_ret:
							self._address = endAddr
							return self.valid

				if operand.type.is_imm:
					if sark.Function.is_function(operand.value):
						endAddr = sark.Function(operand.value).end_ea - 1

						if sark.Line(endAddr).insn.is_ret:
							self._address = endAddr
							return self.valid

		return False

	def scan(self, address, method):
		if method == "direct":
			return self.scandirect(address)

		if method == "retofreferencedfunc":
			return self.scanretofreferencedfunc(address)

		raise ValueError("unimplemented scan type", self, method)

class Vtable(Entry):
	@property
	def valid(self):
		if not self._address:
			return False

		return True

	def scan(self, address, method):
		line = sark.Line(address)

		if line.is_code:
			for operand in line.insn.operands:
				if operand.type.has_phrase:
					self._address = operand.offset / 4
					return self.valid

		return False

class Instance(Entry):
	@property
	def valid(self):
		if not self._address:
			return False

		return sark.Line(self._address).is_data

	def scanreference(self, address):
		line = sark.Line(address)

		if line.is_code:
			for operand in line.insn.operands:
				if operand.type.is_imm:
					self._address = operand.value
					return self.valid

				if operand.type.is_mem:
					self._address = operand.offset
					return self.valid

		return False

	def scan(self, address, method):
		if method == "reference":
			return self.scanreference(address)

		raise ValueError("unimplemented scan type", self, method)

	def definename(self, enum_name):
		addr = self.address

		if addr and self.valid:
			sark.set_name(addr, "{}_{}".format(enum_name, self.name), True)

class Offset(Entry):
	def __init__(self, json):
		Entry.__init__(self, json)
		self._rebase = False

		if "hardcoded" in json:
			self._hardcoded = json["hardcoded"]
		else:
			self._hardcoded = None

		if "relative" in json:
			self._relative = json["relative"]
		else:
			self._relative = None

	@property
	def valid(self):
		if not self._address:
			return False

		# perhaps add some type of sanity checking?
		return True

	def scanreference(self, address):
		line = sark.Line(address)

		if line.is_code:
			for operand in line.insn.operands:
				if operand.type.is_imm:
					self._address = operand.value
					return self.valid

		return False

	def scanphrase(self, address):
		line = sark.Line(address)

		if line.is_code:
			for operand in line.insn.operands:
				if operand.type.has_phrase:
					self._address = operand.offset
					return self.valid

		return False

	def scan(self, address, method):
		if method == "phrase":
			return self.scanphrase(address)

		if method == "reference":
			return self.scanreference(address)

		raise ValueError("unimplemented scan type", self, method)

	@property
	def cppstring(self):
		if not self.shouldenum:
			return ""

		if self._hardcoded:
			return "\t\t{} = {},\n".format(self.name, self._hardcoded)

		addr = self.address
		if self._rebase:
			addr = max(0, addr - idaapi.get_imagebase())

		if addr == 0:
			return "\t\t{} = 0x{:02X}, // Failed\n".format(self.name, 0)

		return "\t\t{} = 0x{:02X},\n".format(self.name, addr)


class Function(Entry):
	@property
	def valid(self):
		if not self._address:
			return False

		if sark.Function.is_function(self._address):
			return sark.Function(self._address).start_ea == self._address

		return False

	def scanreference(self, address):
		line = sark.Line(address)

		if line.is_code:
			for operand in line.insn.operands:
				if operand.type.is_near:
					self._address = operand.offset
					return self.valid

				if operand.type.is_imm:
					self._address = operand.value
					return self.valid

		return False

	def scandirect(self, address):
		if sark.Function.is_function(address):
			self._address = sark.Function(address).start_ea
			return True

		return False

	def scan(self, address, method):
		if method == "reference":
			return self.scanreference(address)

		if method == "direct":
			return self.scandirect(address)

		raise ValueError("unimplemented scan type", self, method)

	def definename(self, enum_name):
		addr = self.address

		if addr and self.valid:
			sark.set_name(addr, "{}_{}".format(enum_name, self.name), True)


class Enum:
	def __init__(self, json):
		if "name" not in json:
			raise ValueError(self, "invalid json entry: missing 'name'")

		self.name = json["name"]

		if "dontenum" in json:
			self.dontenum = True
		else:
			self.dontenum = False

		if "instances" in json:
			self.instances = [Instance(x) for x in json["instances"]]
		else:
			self.instances = []

		if "offsets" in json:
			self.offsets = [Offset(x) for x in json["offsets"]]
		else:
			self.offsets = []

		if "functions" in json:
			self.functions = [Function(x) for x in json["functions"]]
		else:
			self.functions = []

		if "addressess" in json:
			self.addressess = [Address(x) for x in json["addressess"]]
		else:
			self.addressess = []

	@property
	def cppstring(self):
		if self.dontenum:
			return ""

		result = "\tenum class {}\n\t{}\n".format(self.name, "{")

		shouldNewLine = False

		for inst in self.instances:
			shouldNewLine = True
			result += inst.cppstring

		shouldNewLine = shouldNewLine and (len(self.addressess) > 0 or len(self.offsets) > 0 or len(self.functions) > 0)

		if shouldNewLine:
			shouldNewLine = False
			result += "\n"

		for off in self.offsets:
			shouldNewLine = True
			result += off.cppstring

		shouldNewLine = shouldNewLine and (len(self.addressess) > 0 or len(self.functions) > 0)

		if shouldNewLine:
			shouldNewLine = False
			result += "\n"

		for func in self.functions:
			shouldNewLine = True
			result += func.cppstring

		shouldNewLine = shouldNewLine and (len(self.addressess) > 0)

		if shouldNewLine:
			shouldNewLine = False
			result += "\n"

		for address in self.addressess:
			result += address.cppstring

		result += "\t};"
		return result

	def definenames(self):
		for obj in self.instances:
			obj.definename(self.name)

		for obj in self.functions:
			obj.definename(self.name)
