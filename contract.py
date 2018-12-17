import logging
import opcodes

log = logging.getLogger(__name__)


class Contract:
    def __init__(self):
        self.blocks = []
        self.jump_destination = {}


class BasicBlock:
    def __init__(self, offset):
        self.offset = offset
        self.instructions = []
        self.next = None
        self.source = None
        self.label = None


class Instruction:
    def __init__(self, op, name, arg):
        self.op = op
        self.name = name
        self.arg = arg
        self.source = None
        self.destination = []


def initialize(evm):
    """
    Initialize the analysis, disassemble the bytecode and construct basic blocks
    """
    contract = Contract()
    current_block = BasicBlock(0)
    i = 0
    while i < len(evm):
        op = evm[i]
        if op not in opcodes.opcodes.keys():
            raise KeyError('Invalid op. op: {:#x}, offset: {:#x}'.format(op, i))

        name = opcodes.opcodes[op][0]
        size = opcodes.operand_size(op)
        if size != 0:
            arg = int.from_bytes(evm[i + 1:i + 1 + size], byteorder='big')
        else:
            arg = None

        if name == 'JUMPDEST':
            if len(current_block.instructions) > 0:
                contract.blocks.append(current_block)
                new_block = BasicBlock(i)
                current_block.next = new_block
                current_block = new_block
            current_block.offset += 1
            contract.jump_destination[i] = current_block
        else:
            instruction = Instruction(op, name, arg)
            current_block.instructions.append(instruction)

            if (name == 'JUMP' or name == 'JUMPI' or name == 'RETURN' or name == 'SUICIDE' or name == 'STOP' or
                    name == 'REVERT'):
                contract.blocks.append(current_block)
                new_block = BasicBlock(i + 1)
                current_block.next = new_block
                current_block = new_block

        i += size + 1

    if len(current_block.instructions) > 0 or current_block.offset in contract.jump_destination.keys():
        contract.blocks.append(current_block)
    else:
        contract.blocks[-1].next = None

    return contract
