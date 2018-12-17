import logging
import opcodes

log = logging.getLogger(__name__)


class State:
    def __init__(self, contract, next_block, stack):
        self.contract = contract
        self.next_block = next_block
        self.stack = stack

    def __eq__(self, other):
        if isinstance(other, State):
            return (id(self.contract) == id(other.contract) and id(self.next_block) == id(other.next_block) and
                    self.stack == other.stack)
        else:
            return NotImplemented

    def __hash__(self):
        return hash((id(self.contract), id(self.next_block), tuple(self.stack)))


class InstructionPointer:
    def __init__(self, block, index):
        self.block = block
        self.index = index

    def __eq__(self, other):
        if isinstance(other, InstructionPointer):
            return id(self.block) == id(other.block) and self.index == other.index
        else:
            return NotImplemented

    def __hash__(self):
        return hash((id(self.block), self.index))


class InstructionOperandPointer:
    def __init__(self, instruction_pointer, pos):
        self.instruction_pointer = instruction_pointer
        self.pos = pos


def update_block_source(block, stack, height):
    """
    Update the source of the block
    """
    source = block.source
    if source is None:
        source = []
        for i in range(height):
            source.append({stack[i]})
    else:
        for i in range(height):
            if len(source) <= i:
                break
            source[i].add(stack[i])

        if height < len(source):
            source = source[:height]
    block.source = source


def get_instruction(pointer):
    """
    Get the instruction from the instruction pointer
    """
    return pointer.block.instructions[pointer.index]


def get_instruction_offset(pointer):
    """
    Get the instruction offset form the instruction pointer
    """
    offset = pointer.block.offset
    for i in range(pointer.index):
        size = opcodes.operand_size(pointer.block.instructions[i].op)
        offset += size + 1
    return offset


def update_instruction_source(instruction, operands, ins):
    """
    Update the source of the instruction's operands
    """
    op = instruction.op
    if opcodes.is_swap(op) or opcodes.is_dup(op):
        return

    source = instruction.source
    if source is None:
        source = []
        for i in range(ins):
            source.append({operands[i]})
    else:
        for i in range(ins):
            source[i].add(operands[i])
    instruction.source = source


def advance(state):
    """
    Execute next block abstractly and advance the current state
    """
    contract = state.contract
    block = state.next_block
    pc = state.next_block.offset
    stack = state.stack.copy()
    update_block_source(block, stack, len(stack))

    for index, instruction in enumerate(state.next_block.instructions):
        op = instruction.op
        name = instruction.name

        old_stack = stack.copy()
        ins = opcodes.opcodes[op][1]
        operands = []
        for i in range(ins):
            operand = stack.pop(0)
            operands.append(operand)
        update_instruction_source(instruction, operands, ins)

        if name == 'STOP' or name == 'RETURN' or name == 'REVERT' or name == 'SUICIDE':
            return []
        elif opcodes.is_push(op):
            stack.insert(0, InstructionPointer(state.next_block, index))
        elif opcodes.is_dup(op):
            old_stack.insert(0, operands[-1])
            stack = old_stack
        elif opcodes.is_swap(op):
            tmp = old_stack[0]
            old_stack[0] = old_stack[ins - 1]
            old_stack[ins - 1] = tmp
            stack = old_stack
        elif name == 'JUMP':
            source_instruction = get_instruction(operands[0])
            if not opcodes.is_push(source_instruction.op):
                raise TypeError('Error resolving JUMP address. pc: {:#x}, source: {:#x}'
                                .format(pc, get_instruction_offset(operands[0])))

            if source_instruction.arg not in contract.jump_destination.keys():
                raise KeyError('Invalid JUMP address. pc: {:#x}, source: {:#x}, addr: {:#x}'
                               .format(pc, get_instruction_offset(operands[0]), source_instruction.arg))

            return [State(contract, contract.jump_destination[source_instruction.arg], stack)]
        elif name == 'JUMPI':
            source_instruction = get_instruction(operands[0])
            if not opcodes.is_push(source_instruction.op):
                raise ValueError('Error resolving JUMP address. pc: {:#x}, source: {:#x}'
                                 .format(pc, get_instruction_offset(operands[0])))

            if source_instruction.arg not in contract.jump_destination.keys():
                raise KeyError('Invalid JUMP address. pc: {:#x}, source: {:#x}, addr: {:#x}'
                               .format(pc, get_instruction_offset(operands[0]), source_instruction.arg))

            ret = [State(contract, contract.jump_destination[source_instruction.arg], stack)]

            if state.next_block.next is not None:
                ret.append(State(contract, state.next_block.next, stack))

            return ret
        else:
            outs = opcodes.opcodes[op][2]
            for i in range(outs):
                stack.insert(0, InstructionPointer(state.next_block, index))

        if len(stack) > 1024:
            log.critical('Stack overflow. pc: {:#x}'.format(pc))
            return []

        size = opcodes.operand_size(op)
        pc += size + 1

    if state.next_block.next is not None:
        return [State(contract, state.next_block.next, stack)]
    else:
        return []


def analyze_source(contract):
    """
    Analyze the source of data flows originated from instructions
    """
    initial_state = State(contract, contract.blocks[0], [])
    state_stack = [initial_state]
    visited_states = {initial_state}

    while len(state_stack) > 0:
        current_state = state_stack.pop(0)
        next_states = advance(current_state)

        for state in next_states:
            if state not in visited_states:
                visited_states.add(state)
                state_stack.insert(0, state)


def analyze_destination(contract):
    """
    Analyze the destination of data flows originated from instructions
    """
    for block in contract.blocks:
        for index, instruction in enumerate(block.instructions):
            op = instruction.op
            if opcodes.is_swap(op) or opcodes.is_dup(op):
                continue

            source = instruction.source
            if source is not None:
                for pos, pointers in enumerate(source):
                    for pointer in pointers:
                        source_instruction = get_instruction(pointer)
                        destination = source_instruction.destination
                        destination.append(InstructionOperandPointer(InstructionPointer(block, index), pos))
                        source_instruction.destination = destination


def label_blocks(contract):
    """
    Label all the blocks
    """
    for block in contract.blocks:
        for index, instruction in enumerate(block.instructions):
            if not opcodes.is_push(instruction.op):
                continue
            if instruction.arg not in contract.jump_destination.keys():
                continue

            destination = instruction.destination
            for operand_pointer in destination:
                instruction_pointer = operand_pointer.instruction_pointer
                destination_instruction = get_instruction(instruction_pointer)
                if destination_instruction.name != 'JUMPI' and destination_instruction.name != 'JUMP':
                    break
                elif operand_pointer.pos != 0:
                    break
            else:
                target_block = contract.jump_destination[instruction.arg]
                target_block.label = -1

    identity = 0
    for block in contract.blocks:
        if block.label is not None:
            block.label = identity
            identity += 1


def execute(contract):
    """
    Analyze the contract, obtain the source and the destination of data flows originated from instructions
    """
    analyze_source(contract)
    analyze_destination(contract)
    label_blocks(contract)

    return contract
