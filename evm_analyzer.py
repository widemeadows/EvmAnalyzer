import argparse
import re
import logging
import time
import signal
import contract
import analyze
import opcodes


def remove_swarm_hash(evm):
    """
    Remove the swarm hash from the raw evm bytecode string
    """
    pattern = re.compile(r'a165627a7a72305820\w{64}0029$', re.A)
    if pattern.search(evm):
        evm = evm[:-86]
    return evm


def print_analysis_result(analyzed_contract):
    """
    Print the analysis result
    """
    result = ''
    for block in analyzed_contract.blocks:
        label = block.label
        if label is not None:
            result += ':label{}\n'.format(label)

        offset = block.offset
        for instruction in block.instructions:
            op = instruction.op
            name = instruction.name
            if opcodes.is_push(op):
                arg = instruction.arg
                result += '{:#x}\t{} {:#x}\n'.format(offset, name, arg)
            elif name == 'JUMPI' or name == 'JUMP':
                result += '{:#x}\t{} '.format(offset, name)
                source_instruction_set = instruction.source[0]
                for pointer in source_instruction_set:
                    source_instruction = analyze.get_instruction(pointer)
                    target_label = analyzed_contract.jump_destination[source_instruction.arg].label
                    result += ':label{} '.format(target_label)
                result = result[:-1] + '\n'
            else:
                result += '{:#x}\t{}\n'.format(offset, name)
            offset += opcodes.operand_size(op) + 1
        result += '\n'

    print(result)


def signal_handler(signum, frame):
    """
    The signal handler function
    """
    raise Exception("timeout")


def main():
    """
    Program entry
    """
    parser = argparse.ArgumentParser(description='An EVM ByteCode Analyzer')
    parser.add_argument('-b', '--bytecode',
                        type=str, required=True, help='EVM bytecode file name')
    parser.add_argument('-t', '--timeout',
                        type=int, default=30, help="Timeout for analysis in seconds (default to 30 seconds)")
    parser.add_argument('-d', '--debug',
                        action='store_true', help='debug output')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    with open(args.bytecode) as f:
        raw_evm_string = f.read()
        evm_string = remove_swarm_hash(raw_evm_string)

    # Convert the evm bytecode string to bytes
    evm_bytes = bytes.fromhex(evm_string)

    initialed_contract = contract.initialize(evm_bytes)

    start_time = time.time()
    if hasattr(signal, 'SIGALRM'):
        signal.signal(signal.SIGALRM, signal_handler)
        signal.alarm(args.timeout)

    timeout = False
    try:
        analyzed_contract = analyze.execute(initialed_contract)
    except Exception as err:
        if str(err) == 'timeout':
            timeout = True
        else:
            raise err

    end_time = time.time()
    if callable(getattr(signal, 'alarm', None)):
        signal.alarm(0)

    if not timeout:
        print_analysis_result(analyzed_contract)
    else:
        print('[!] Analysis Timeout!')

    print('[*] Total Analysis Time:{:.5f} seconds'.format(end_time - start_time))


if __name__ == '__main__':
    main()
