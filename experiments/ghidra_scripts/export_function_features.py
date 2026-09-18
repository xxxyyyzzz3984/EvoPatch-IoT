# Export stripped-compatible function features from the current Ghidra program.
#
# Arguments:
#   0 output_jsonl
#   1 summary_json
#   2 binary_id
#   3 version
#   4 arch
#   5 input_path
#   6 max_tokens
#   7 max_functions

import io
import json
import re
import time

from ghidra.program.model.address import Address
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.lang import Register
from ghidra.program.model.scalar import Scalar
from ghidra.util.task import ConsoleTaskMonitor


MOVE = set(["mov", "move", "movz", "movn", "lea", "li", "la", "adr", "adrp", "csel"])
LOAD_PREFIXES = ("ldr", "ld", "lw", "lh", "lb", "lbu", "lhu", "ldu", "movsx", "movzx")
STORE_PREFIXES = ("str", "st", "sw", "sh", "sb")
ARITH_PREFIXES = ("add", "sub", "mul", "imul", "div", "idiv", "madd", "msub", "neg", "inc", "dec")
LOGIC_PREFIXES = ("and", "orr", "or", "xor", "eor", "not", "bic", "nor")
SHIFT_PREFIXES = ("shl", "shr", "sar", "sal", "sll", "srl", "sra", "lsl", "lsr", "asr", "ror", "rol")
CMP_PREFIXES = ("cmp", "cmn", "test", "tst", "slt", "slti")
CALL = set(["call", "bl", "blr", "jal", "jalr", "bal"])
RET = set(["ret", "retn", "eret", "bx", "jr"])
SYSCALL = set(["syscall", "svc", "swi", "int"])
UNCOND_BRANCH = set(["jmp", "j", "b", "br", "bra"])
COND_BRANCH_PREFIXES = (
    "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle",
    "jo", "jno", "js", "jns", "jp", "jnp", "beq", "bne", "bgt", "bge", "blt", "ble",
    "bhi", "bls", "bcs", "bcc", "cbz", "cbnz", "tbz", "tbnz",
)
STACK_NAMES = ("sp", "rsp", "esp", "rbp", "ebp", "$sp", "r11", "fp", "x29")


def as_hex(addr):
    try:
        return "0x%x" % addr.getOffset()
    except Exception:
        return str(addr)


def classify_mnemonic(mnemonic):
    m = mnemonic.lower().strip()
    if not m:
        return "OTHER"
    m = m.split(".")[0]
    if m in CALL:
        return "CALL"
    if m in RET:
        return "RET"
    if m in SYSCALL:
        return "SYSCALL"
    if m in MOVE:
        return "MOVE"
    if m.startswith(LOAD_PREFIXES):
        return "LOAD"
    if m.startswith(STORE_PREFIXES):
        return "STORE"
    if m.startswith(ARITH_PREFIXES):
        return "ARITH"
    if m.startswith(LOGIC_PREFIXES):
        return "LOGIC"
    if m.startswith(SHIFT_PREFIXES):
        return "SHIFT"
    if m.startswith(CMP_PREFIXES):
        return "CMP"
    if m in UNCOND_BRANCH:
        return "BRANCH_UNCOND"
    if m.startswith(COND_BRANCH_PREFIXES) or mnemonic.lower().startswith("b."):
        return "BRANCH_COND"
    if m.startswith("push") or m.startswith("pop") or m in set(["enter", "leave", "stp", "ldp"]):
        return "STACK"
    return "OTHER"


def imm_bucket(value):
    try:
        value = int(value)
    except Exception:
        return "IMM"
    if value == 0:
        return "IMM_ZERO"
    if value == 1:
        return "IMM_ONE"
    if value < 0:
        return "IMM_NEG"
    if value <= 0xff:
        return "IMM_SMALL"
    if value <= 0xffff:
        return "IMM_MEDIUM"
    if value & (value - 1) == 0:
        return "IMM_MASK"
    return "IMM_LARGE"


def operand_role(inst, index):
    text = ""
    try:
        text = inst.getDefaultOperandRepresentation(index).lower()
    except Exception:
        text = ""
    try:
        objects = list(inst.getOpObjects(index))
    except Exception:
        objects = []
    has_reg = False
    has_scalar = False
    has_address = False
    scalar_value = None
    for obj in objects:
        if isinstance(obj, Register):
            has_reg = True
        elif isinstance(obj, Scalar):
            has_scalar = True
            try:
                scalar_value = obj.getSignedValue()
            except Exception:
                scalar_value = obj.getValue()
        elif isinstance(obj, Address):
            has_address = True

    is_memory = ("[" in text and "]" in text) or ("(" in text and ")" in text)
    if is_memory:
        if any(name in text for name in STACK_NAMES):
            return "MEM_STACK"
        return "MEM"
    if has_address:
        return "ADDR"
    if has_reg:
        return "REG"
    if has_scalar:
        return imm_bucket(scalar_value)
    if text:
        return "OPERAND"
    return "NONE"


def instruction_token(inst):
    op_class = classify_mnemonic(inst.getMnemonicString())
    roles = []
    try:
        count = inst.getNumOperands()
    except Exception:
        count = 0
    for idx in range(count):
        role = operand_role(inst, idx)
        if role != "NONE":
            roles.append(role)
    if not roles:
        return op_class
    return op_class + " " + " ".join(roles)


def collect_constant_buckets(inst):
    buckets = []
    try:
        count = inst.getNumOperands()
    except Exception:
        count = 0
    for idx in range(count):
        try:
            objects = list(inst.getOpObjects(idx))
        except Exception:
            objects = []
        for obj in objects:
            if isinstance(obj, Scalar):
                try:
                    buckets.append(imm_bucket(obj.getSignedValue()))
                except Exception:
                    buckets.append(imm_bucket(obj.getValue()))
    return buckets


def string_category(value):
    s = value or ""
    lower = s.lower()
    if re.match(r"^[0-9]+$", lower):
        category = "numeric"
    elif "://" in lower or lower.startswith("www."):
        category = "url_like"
    elif "/" in lower or "\\" in lower:
        category = "path_like"
    elif lower.startswith("-"):
        category = "option_like"
    elif "%" in lower:
        category = "format_like"
    elif any(word in lower for word in ["error", "failed", "invalid", "usage"]):
        category = "message_like"
    else:
        category = "other"
    length = len(s)
    if length <= 8:
        bucket = "len_0_8"
    elif length <= 32:
        bucket = "len_9_32"
    elif length <= 128:
        bucket = "len_33_128"
    else:
        bucket = "len_129_plus"
    return category + ":" + bucket


def collect_string_categories(inst, listing):
    categories = []
    try:
        refs = inst.getReferencesFrom()
    except Exception:
        refs = []
    for ref in refs:
        try:
            to_addr = ref.getToAddress()
            if to_addr is None or to_addr.isExternalAddress():
                continue
            data = listing.getDataAt(to_addr)
            if data is None:
                continue
            value = data.getValue()
            if value is None:
                continue
            has_string_value = False
            try:
                has_string_value = data.hasStringValue()
            except Exception:
                has_string_value = False
            if has_string_value or isinstance(value, basestring):
                categories.append(string_category(str(value)))
        except Exception:
            continue
    return categories


def block_ranges(function, block_model, monitor):
    body = function.getBody()
    blocks = []
    edges = []
    block_iter = block_model.getCodeBlocksContaining(body, monitor)
    index_by_start = {}
    while block_iter.hasNext():
        block = block_iter.next()
        start = block.getFirstStartAddress()
        index = len(blocks)
        index_by_start[str(start)] = index
        blocks.append({
            "id": index,
            "start_addr": as_hex(start),
            "end_addr": as_hex(block.getMaxAddress()),
            "size": int(block.getNumAddresses()),
        })

    block_iter = block_model.getCodeBlocksContaining(body, monitor)
    while block_iter.hasNext():
        block = block_iter.next()
        src = index_by_start.get(str(block.getFirstStartAddress()))
        if src is None:
            continue
        try:
            dest_iter = block.getDestinations(monitor)
            while dest_iter.hasNext():
                dest_ref = dest_iter.next()
                dest_block = dest_ref.getDestinationBlock()
                if dest_block is None:
                    continue
                dest_start = dest_block.getFirstStartAddress()
                dst = index_by_start.get(str(dest_start))
                if dst is None:
                    continue
                try:
                    edge_type = str(dest_ref.getFlowType())
                except Exception:
                    edge_type = "unknown"
                edges.append([src, dst, edge_type])
        except Exception:
            continue
    return blocks, edges


def function_record(function, listing, block_model, monitor, meta, max_tokens):
    body = function.getBody()
    entry = function.getEntryPoint()
    tokens = []
    constants = []
    strings = []
    call_refs = []
    raw_instruction_count = 0
    branch_count = 0
    call_count = 0
    ret_count = 0

    inst_iter = listing.getInstructions(body, True)
    while inst_iter.hasNext():
        inst = inst_iter.next()
        raw_instruction_count += 1
        op_class = classify_mnemonic(inst.getMnemonicString())
        if len(tokens) < max_tokens:
            tokens.append(instruction_token(inst))
        constants.extend(collect_constant_buckets(inst))
        strings.extend(collect_string_categories(inst, listing))
        if op_class in ("BRANCH_COND", "BRANCH_UNCOND"):
            branch_count += 1
        elif op_class == "CALL":
            call_count += 1
            ref_kind = "indirect"
            target = ""
            try:
                refs = inst.getReferencesFrom()
                for ref in refs:
                    to_addr = ref.getToAddress()
                    if to_addr is not None:
                        target = as_hex(to_addr)
                        ref_kind = "external" if to_addr.isExternalAddress() else "internal"
                        break
            except Exception:
                pass
            call_refs.append({"site": as_hex(inst.getAddress()), "target": target, "kind": ref_kind})
        elif op_class == "RET":
            ret_count += 1

    basic_blocks, cfg_edges = block_ranges(function, block_model, monitor)
    constants_hist = {}
    for bucket in constants:
        constants_hist[bucket] = constants_hist.get(bucket, 0) + 1
    string_hist = {}
    for category in strings:
        string_hist[category] = string_hist.get(category, 0) + 1

    function_id = "%s-func-%s" % (meta["binary_id"], as_hex(entry).replace("0x", ""))
    return {
        "function_id": function_id,
        "binary_id": meta["binary_id"],
        "version": meta["version"],
        "arch": meta["arch"],
        "start_addr": as_hex(entry),
        "size": int(body.getNumAddresses()),
        "tokens": tokens,
        "token_truncated": int(raw_instruction_count > len(tokens)),
        "basic_blocks": basic_blocks,
        "cfg_edges": cfg_edges,
        "call_refs": call_refs,
        "string_refs": [{"category": key, "count": value} for key, value in sorted(string_hist.items())],
        "constant_buckets": [{"bucket": key, "count": value} for key, value in sorted(constants_hist.items())],
        "stats": {
            "instruction_count": raw_instruction_count,
            "basic_block_count": len(basic_blocks),
            "cfg_edge_count": len(cfg_edges),
            "call_count": call_count,
            "branch_count": branch_count,
            "ret_count": ret_count,
            "string_ref_count": len(strings),
            "constant_count": len(constants),
        },
        "provenance": {
            "input_path": meta["input_path"],
            "ghidra_language_id": meta["language_id"],
            "ghidra_compiler_spec_id": meta["compiler_spec_id"],
            "extractor": "ghidra_scripts/export_function_features.py",
        },
    }


def main():
    args = getScriptArgs()
    if len(args) < 8:
        raise RuntimeError("Expected 8 script arguments, got %d" % len(args))
    output_jsonl = args[0]
    summary_json = args[1]
    max_tokens = int(args[6])
    max_functions = int(args[7])
    started = time.time()

    program = currentProgram
    listing = program.getListing()
    function_manager = program.getFunctionManager()
    monitor = ConsoleTaskMonitor()
    block_model = BasicBlockModel(program)
    meta = {
        "binary_id": args[2],
        "version": args[3],
        "arch": args[4],
        "input_path": args[5],
        "language_id": str(program.getLanguageID()),
        "compiler_spec_id": str(program.getCompilerSpec().getCompilerSpecID()),
    }

    count = 0
    total_instructions = 0
    total_blocks = 0
    with io.open(output_jsonl, "w", encoding="utf-8") as out:
        functions = function_manager.getFunctions(True)
        while functions.hasNext():
            function = functions.next()
            if max_functions > 0 and count >= max_functions:
                break
            try:
                if function.isExternal() or function.getBody() is None or function.getBody().isEmpty():
                    continue
                rec = function_record(function, listing, block_model, monitor, meta, max_tokens)
                out.write(json.dumps(rec, sort_keys=True) + "\n")
                count += 1
                total_instructions += int(rec["stats"]["instruction_count"])
                total_blocks += int(rec["stats"]["basic_block_count"])
            except Exception as exc:
                err = {
                    "binary_id": meta["binary_id"],
                    "version": meta["version"],
                    "arch": meta["arch"],
                    "error": str(exc),
                    "function_start_addr": as_hex(function.getEntryPoint()),
                }
                out.write(json.dumps({"extract_error": err}, sort_keys=True) + "\n")

    summary = {
        "status": "completed",
        "binary_id": meta["binary_id"],
        "version": meta["version"],
        "arch": meta["arch"],
        "input_path": meta["input_path"],
        "output_jsonl": output_jsonl,
        "function_count": count,
        "total_instructions": total_instructions,
        "total_basic_blocks": total_blocks,
        "max_tokens": max_tokens,
        "max_functions": max_functions,
        "duration_sec": round(time.time() - started, 3),
        "ghidra_language_id": meta["language_id"],
        "ghidra_compiler_spec_id": meta["compiler_spec_id"],
    }
    with io.open(summary_json, "w", encoding="utf-8") as f:
        f.write(json.dumps(summary, indent=2, sort_keys=True))
        f.write("\n")


main()
