// Export stripped-compatible function features from the current Ghidra program.
//
// Arguments:
//   0 output_jsonl
//   1 summary_json
//   2 binary_id
//   3 version
//   4 arch
//   5 input_path
//   6 max_tokens
//   7 max_functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

public class ExportFunctionFeatures extends GhidraScript {
    private static final Set<String> MOVE = new HashSet<String>(Arrays.asList(
        "mov", "move", "movz", "movn", "lea", "li", "la", "adr", "adrp", "csel"
    ));
    private static final Set<String> CALL = new HashSet<String>(Arrays.asList(
        "call", "bl", "blr", "jal", "jalr", "bal"
    ));
    private static final Set<String> RET = new HashSet<String>(Arrays.asList(
        "ret", "retn", "eret", "bx", "jr"
    ));
    private static final Set<String> SYSCALL = new HashSet<String>(Arrays.asList(
        "syscall", "svc", "swi", "int"
    ));
    private static final Set<String> UNCOND_BRANCH = new HashSet<String>(Arrays.asList(
        "jmp", "j", "b", "br", "bra"
    ));
    private static final String[] LOAD_PREFIXES = {"ldr", "ld", "lw", "lh", "lb", "lbu", "lhu", "ldu", "movsx", "movzx"};
    private static final String[] STORE_PREFIXES = {"str", "st", "sw", "sh", "sb"};
    private static final String[] ARITH_PREFIXES = {"add", "sub", "mul", "imul", "div", "idiv", "madd", "msub", "neg", "inc", "dec"};
    private static final String[] LOGIC_PREFIXES = {"and", "orr", "or", "xor", "eor", "not", "bic", "nor"};
    private static final String[] SHIFT_PREFIXES = {"shl", "shr", "sar", "sal", "sll", "srl", "sra", "lsl", "lsr", "asr", "ror", "rol"};
    private static final String[] CMP_PREFIXES = {"cmp", "cmn", "test", "tst", "slt", "slti"};
    private static final String[] COND_BRANCH_PREFIXES = {
        "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle",
        "jo", "jno", "js", "jns", "jp", "jnp", "beq", "bne", "bgt", "bge", "blt", "ble",
        "bhi", "bls", "bcs", "bcc", "cbz", "cbnz", "tbz", "tbnz"
    };
    private static final String[] STACK_NAMES = {"sp", "rsp", "esp", "rbp", "ebp", "$sp", "r11", "fp", "x29"};

    private String binaryId;
    private String version;
    private String arch;
    private String inputPath;
    private int maxTokens;
    private int maxFunctions;
    private Listing listing;
    private BasicBlockModel blockModel;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 8) {
            throw new IllegalArgumentException("Expected 8 script arguments, got " + args.length);
        }
        String outputJsonl = args[0];
        String summaryJson = args[1];
        binaryId = args[2];
        version = args[3];
        arch = args[4];
        inputPath = args[5];
        maxTokens = Integer.parseInt(args[6]);
        maxFunctions = Integer.parseInt(args[7]);
        listing = currentProgram.getListing();
        blockModel = new BasicBlockModel(currentProgram);
        long started = System.currentTimeMillis();

        ensureParent(outputJsonl);
        ensureParent(summaryJson);
        int functionCount = 0;
        long totalInstructions = 0;
        long totalBlocks = 0;

        BufferedWriter out = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(outputJsonl), StandardCharsets.UTF_8));
        try {
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                if (maxFunctions > 0 && functionCount >= maxFunctions) {
                    break;
                }
                Function function = functions.next();
                if (function.isExternal() || function.getBody() == null || function.getBody().isEmpty()) {
                    continue;
                }
                try {
                    FunctionRecord rec = collectFunction(function);
                    out.write(toJson(rec));
                    out.newLine();
                    functionCount++;
                    totalInstructions += rec.instructionCount;
                    totalBlocks += rec.basicBlocks.size();
                }
                catch (Exception exc) {
                    out.write(errorJson(function, exc));
                    out.newLine();
                }
            }
        }
        finally {
            out.close();
        }

        double durationSec = (System.currentTimeMillis() - started) / 1000.0;
        BufferedWriter summary = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(summaryJson), StandardCharsets.UTF_8));
        try {
            summary.write("{\n");
            summary.write("  \"status\": \"completed\",\n");
            summary.write("  \"binary_id\": " + quote(binaryId) + ",\n");
            summary.write("  \"version\": " + quote(version) + ",\n");
            summary.write("  \"arch\": " + quote(arch) + ",\n");
            summary.write("  \"input_path\": " + quote(inputPath) + ",\n");
            summary.write("  \"output_jsonl\": " + quote(outputJsonl) + ",\n");
            summary.write("  \"function_count\": " + functionCount + ",\n");
            summary.write("  \"total_instructions\": " + totalInstructions + ",\n");
            summary.write("  \"total_basic_blocks\": " + totalBlocks + ",\n");
            summary.write("  \"max_tokens\": " + maxTokens + ",\n");
            summary.write("  \"max_functions\": " + maxFunctions + ",\n");
            summary.write("  \"duration_sec\": " + String.format(java.util.Locale.US, "%.3f", durationSec) + ",\n");
            summary.write("  \"ghidra_language_id\": " + quote(currentProgram.getLanguageID().toString()) + ",\n");
            summary.write("  \"ghidra_compiler_spec_id\": " + quote(currentProgram.getCompilerSpec().getCompilerSpecID().toString()) + "\n");
            summary.write("}\n");
        }
        finally {
            summary.close();
        }
    }

    private FunctionRecord collectFunction(Function function) throws Exception {
        FunctionRecord rec = new FunctionRecord();
        rec.functionId = binaryId + "-func-" + asHex(function.getEntryPoint()).replace("0x", "");
        rec.startAddr = asHex(function.getEntryPoint());
        rec.size = function.getBody().getNumAddresses();
        rec.tokens = new ArrayList<String>();
        rec.constantBuckets = new TreeMap<String, Integer>();
        rec.stringRefs = new TreeMap<String, Integer>();
        rec.callRefs = new ArrayList<CallRef>();

        InstructionIterator iter = listing.getInstructions(function.getBody(), true);
        while (iter.hasNext()) {
            Instruction inst = iter.next();
            rec.instructionCount++;
            String opClass = classifyMnemonic(inst.getMnemonicString());
            if (rec.tokens.size() < maxTokens) {
                rec.tokens.add(instructionToken(inst));
            }
            for (String bucket : collectConstantBuckets(inst)) {
                increment(rec.constantBuckets, bucket);
                rec.constantCount++;
            }
            for (String category : collectStringCategories(inst)) {
                increment(rec.stringRefs, category);
                rec.stringRefCount++;
            }
            if ("BRANCH_COND".equals(opClass) || "BRANCH_UNCOND".equals(opClass)) {
                rec.branchCount++;
            }
            else if ("CALL".equals(opClass)) {
                rec.callCount++;
                rec.callRefs.add(callRef(inst));
            }
            else if ("RET".equals(opClass)) {
                rec.retCount++;
            }
        }
        rec.tokenTruncated = rec.instructionCount > rec.tokens.size();
        collectBlocks(function, rec);
        return rec;
    }

    private void collectBlocks(Function function, FunctionRecord rec) throws Exception {
        Map<String, Integer> indexByStart = new HashMap<String, Integer>();
        CodeBlockIterator blocks = blockModel.getCodeBlocksContaining(function.getBody(), monitor);
        while (blocks.hasNext()) {
            CodeBlock block = blocks.next();
            int id = rec.basicBlocks.size();
            indexByStart.put(block.getFirstStartAddress().toString(), id);
            rec.basicBlocks.add(new BasicBlockRec(id, asHex(block.getFirstStartAddress()), asHex(block.getMaxAddress()), block.getNumAddresses()));
        }
        blocks = blockModel.getCodeBlocksContaining(function.getBody(), monitor);
        while (blocks.hasNext()) {
            CodeBlock block = blocks.next();
            Integer src = indexByStart.get(block.getFirstStartAddress().toString());
            if (src == null) {
                continue;
            }
            CodeBlockReferenceIterator dests = block.getDestinations(monitor);
            while (dests.hasNext()) {
                CodeBlockReference destRef = dests.next();
                CodeBlock destBlock = destRef.getDestinationBlock();
                if (destBlock == null) {
                    continue;
                }
                Integer dst = indexByStart.get(destBlock.getFirstStartAddress().toString());
                if (dst == null) {
                    continue;
                }
                rec.cfgEdges.add(new CfgEdge(src, dst, destRef.getFlowType().toString()));
            }
        }
    }

    private CallRef callRef(Instruction inst) {
        CallRef ref = new CallRef();
        ref.site = asHex(inst.getAddress());
        ref.kind = "indirect";
        ref.target = "";
        try {
            for (Reference r : inst.getReferencesFrom()) {
                Address toAddr = r.getToAddress();
                if (toAddr != null) {
                    ref.target = asHex(toAddr);
                    ref.kind = toAddr.isExternalAddress() ? "external" : "internal";
                    break;
                }
            }
        }
        catch (Exception ignored) {
        }
        return ref;
    }

    private String instructionToken(Instruction inst) {
        String opClass = classifyMnemonic(inst.getMnemonicString());
        List<String> roles = new ArrayList<String>();
        for (int i = 0; i < inst.getNumOperands(); i++) {
            String role = operandRole(inst, i);
            if (!"NONE".equals(role)) {
                roles.add(role);
            }
        }
        if (roles.isEmpty()) {
            return opClass;
        }
        return opClass + " " + joinStrings(roles, " ");
    }

    private String operandRole(Instruction inst, int index) {
        String text = "";
        try {
            text = inst.getDefaultOperandRepresentation(index).toLowerCase();
        }
        catch (Exception ignored) {
        }
        boolean hasReg = false;
        boolean hasScalar = false;
        boolean hasAddress = false;
        long scalarValue = 0;
        Object[] objects = inst.getOpObjects(index);
        for (Object obj : objects) {
            if (obj instanceof Register) {
                hasReg = true;
            }
            else if (obj instanceof Scalar) {
                hasScalar = true;
                scalarValue = ((Scalar) obj).getSignedValue();
            }
            else if (obj instanceof Address) {
                hasAddress = true;
            }
        }
        boolean memory = (text.indexOf("[") >= 0 && text.indexOf("]") >= 0) || (text.indexOf("(") >= 0 && text.indexOf(")") >= 0);
        if (memory) {
            for (String name : STACK_NAMES) {
                if (text.indexOf(name) >= 0) {
                    return "MEM_STACK";
                }
            }
            return "MEM";
        }
        if (hasAddress) {
            return "ADDR";
        }
        if (hasReg) {
            return "REG";
        }
        if (hasScalar) {
            return immBucket(scalarValue);
        }
        return text.length() > 0 ? "OPERAND" : "NONE";
    }

    private List<String> collectConstantBuckets(Instruction inst) {
        List<String> buckets = new ArrayList<String>();
        for (int i = 0; i < inst.getNumOperands(); i++) {
            Object[] objects = inst.getOpObjects(i);
            for (Object obj : objects) {
                if (obj instanceof Scalar) {
                    buckets.add(immBucket(((Scalar) obj).getSignedValue()));
                }
            }
        }
        return buckets;
    }

    private List<String> collectStringCategories(Instruction inst) {
        List<String> categories = new ArrayList<String>();
        try {
            for (Reference ref : inst.getReferencesFrom()) {
                Address toAddr = ref.getToAddress();
                if (toAddr == null || toAddr.isExternalAddress()) {
                    continue;
                }
                Data data = listing.getDataAt(toAddr);
                if (data == null) {
                    continue;
                }
                Object value = data.getValue();
                if (value instanceof String) {
                    categories.add(stringCategory((String) value));
                }
            }
        }
        catch (Exception ignored) {
        }
        return categories;
    }

    private String classifyMnemonic(String mnemonic) {
        String m = mnemonic == null ? "" : mnemonic.toLowerCase().trim();
        int dot = m.indexOf(".");
        if (dot >= 0) {
            m = m.substring(0, dot);
        }
        if (CALL.contains(m)) return "CALL";
        if (RET.contains(m)) return "RET";
        if (SYSCALL.contains(m)) return "SYSCALL";
        if (MOVE.contains(m)) return "MOVE";
        if (startsWithAny(m, LOAD_PREFIXES)) return "LOAD";
        if (startsWithAny(m, STORE_PREFIXES)) return "STORE";
        if (startsWithAny(m, ARITH_PREFIXES)) return "ARITH";
        if (startsWithAny(m, LOGIC_PREFIXES)) return "LOGIC";
        if (startsWithAny(m, SHIFT_PREFIXES)) return "SHIFT";
        if (startsWithAny(m, CMP_PREFIXES)) return "CMP";
        if (UNCOND_BRANCH.contains(m)) return "BRANCH_UNCOND";
        if (startsWithAny(m, COND_BRANCH_PREFIXES) || mnemonic.toLowerCase().startsWith("b.")) return "BRANCH_COND";
        if (m.startsWith("push") || m.startsWith("pop") || "enter".equals(m) || "leave".equals(m) || "stp".equals(m) || "ldp".equals(m)) return "STACK";
        return "OTHER";
    }

    private String stringCategory(String value) {
        String s = value == null ? "" : value;
        String lower = s.toLowerCase();
        String category;
        if (lower.matches("^[0-9]+$")) category = "numeric";
        else if (lower.indexOf("://") >= 0 || lower.startsWith("www.")) category = "url_like";
        else if (lower.indexOf("/") >= 0 || lower.indexOf("\\") >= 0) category = "path_like";
        else if (lower.startsWith("-")) category = "option_like";
        else if (lower.indexOf("%") >= 0) category = "format_like";
        else if (lower.indexOf("error") >= 0 || lower.indexOf("failed") >= 0 || lower.indexOf("invalid") >= 0 || lower.indexOf("usage") >= 0) category = "message_like";
        else category = "other";
        int length = s.length();
        String bucket = length <= 8 ? "len_0_8" : (length <= 32 ? "len_9_32" : (length <= 128 ? "len_33_128" : "len_129_plus"));
        return category + ":" + bucket;
    }

    private String immBucket(long value) {
        if (value == 0) return "IMM_ZERO";
        if (value == 1) return "IMM_ONE";
        if (value < 0) return "IMM_NEG";
        if (value <= 0xffL) return "IMM_SMALL";
        if (value <= 0xffffL) return "IMM_MEDIUM";
        if ((value & (value - 1)) == 0) return "IMM_MASK";
        return "IMM_LARGE";
    }

    private String toJson(FunctionRecord rec) {
        StringBuilder sb = new StringBuilder(4096);
        sb.append("{");
        field(sb, "function_id", rec.functionId).append(",");
        field(sb, "binary_id", binaryId).append(",");
        field(sb, "version", version).append(",");
        field(sb, "arch", arch).append(",");
        field(sb, "start_addr", rec.startAddr).append(",");
        sb.append("\"size\":").append(rec.size).append(",");
        sb.append("\"tokens\":").append(stringArray(rec.tokens)).append(",");
        sb.append("\"token_truncated\":").append(rec.tokenTruncated ? 1 : 0).append(",");
        sb.append("\"basic_blocks\":").append(basicBlocksJson(rec.basicBlocks)).append(",");
        sb.append("\"cfg_edges\":").append(cfgEdgesJson(rec.cfgEdges)).append(",");
        sb.append("\"call_refs\":").append(callRefsJson(rec.callRefs)).append(",");
        sb.append("\"string_refs\":").append(countMapJson(rec.stringRefs, "category")).append(",");
        sb.append("\"constant_buckets\":").append(countMapJson(rec.constantBuckets, "bucket")).append(",");
        sb.append("\"stats\":{");
        sb.append("\"instruction_count\":").append(rec.instructionCount).append(",");
        sb.append("\"basic_block_count\":").append(rec.basicBlocks.size()).append(",");
        sb.append("\"cfg_edge_count\":").append(rec.cfgEdges.size()).append(",");
        sb.append("\"call_count\":").append(rec.callCount).append(",");
        sb.append("\"branch_count\":").append(rec.branchCount).append(",");
        sb.append("\"ret_count\":").append(rec.retCount).append(",");
        sb.append("\"string_ref_count\":").append(rec.stringRefCount).append(",");
        sb.append("\"constant_count\":").append(rec.constantCount).append("},");
        sb.append("\"provenance\":{");
        field(sb, "input_path", inputPath).append(",");
        field(sb, "ghidra_language_id", currentProgram.getLanguageID().toString()).append(",");
        field(sb, "ghidra_compiler_spec_id", currentProgram.getCompilerSpec().getCompilerSpecID().toString()).append(",");
        field(sb, "extractor", "ghidra_scripts/ExportFunctionFeatures.java");
        sb.append("}}");
        return sb.toString();
    }

    private String errorJson(Function function, Exception exc) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"extract_error\":{");
        field(sb, "binary_id", binaryId).append(",");
        field(sb, "version", version).append(",");
        field(sb, "arch", arch).append(",");
        field(sb, "error", exc.toString()).append(",");
        field(sb, "function_start_addr", asHex(function.getEntryPoint()));
        sb.append("}}");
        return sb.toString();
    }

    private String basicBlocksJson(List<BasicBlockRec> blocks) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (int i = 0; i < blocks.size(); i++) {
            if (i > 0) sb.append(",");
            BasicBlockRec b = blocks.get(i);
            sb.append("{\"id\":").append(b.id)
              .append(",\"start_addr\":").append(quote(b.start))
              .append(",\"end_addr\":").append(quote(b.end))
              .append(",\"size\":").append(b.size).append("}");
        }
        sb.append("]");
        return sb.toString();
    }

    private String cfgEdgesJson(List<CfgEdge> edges) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (int i = 0; i < edges.size(); i++) {
            if (i > 0) sb.append(",");
            CfgEdge e = edges.get(i);
            sb.append("[").append(e.src).append(",").append(e.dst).append(",").append(quote(e.type)).append("]");
        }
        sb.append("]");
        return sb.toString();
    }

    private String callRefsJson(List<CallRef> refs) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (int i = 0; i < refs.size(); i++) {
            if (i > 0) sb.append(",");
            CallRef r = refs.get(i);
            sb.append("{\"site\":").append(quote(r.site))
              .append(",\"target\":").append(quote(r.target))
              .append(",\"kind\":").append(quote(r.kind)).append("}");
        }
        sb.append("]");
        return sb.toString();
    }

    private String countMapJson(Map<String, Integer> map, String keyName) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        boolean first = true;
        for (Map.Entry<String, Integer> entry : map.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            sb.append("{").append(quote(keyName)).append(":").append(quote(entry.getKey()))
              .append(",\"count\":").append(entry.getValue()).append("}");
        }
        sb.append("]");
        return sb.toString();
    }

    private String stringArray(List<String> values) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(quote(values.get(i)));
        }
        sb.append("]");
        return sb.toString();
    }

    private StringBuilder field(StringBuilder sb, String key, String value) {
        sb.append(quote(key)).append(":").append(quote(value));
        return sb;
    }

    private String quote(String value) {
        if (value == null) return "null";
        StringBuilder sb = new StringBuilder(value.length() + 8);
        sb.append("\"");
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '\\': sb.append("\\\\"); break;
                case '"': sb.append("\\\""); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (ch < 0x20) sb.append(String.format("\\u%04x", (int) ch));
                    else sb.append(ch);
            }
        }
        sb.append("\"");
        return sb.toString();
    }

    private boolean startsWithAny(String value, String[] prefixes) {
        for (String prefix : prefixes) {
            if (value.startsWith(prefix)) return true;
        }
        return false;
    }

    private void increment(Map<String, Integer> map, String key) {
        Integer value = map.get(key);
        map.put(key, value == null ? 1 : value + 1);
    }

    private String joinStrings(List<String> values, String sep) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) sb.append(sep);
            sb.append(values.get(i));
        }
        return sb.toString();
    }

    private void ensureParent(String path) {
        File parent = new File(path).getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
    }

    private String asHex(Address address) {
        return "0x" + Long.toHexString(address.getOffset());
    }

    private static class FunctionRecord {
        String functionId;
        String startAddr;
        long size;
        List<String> tokens = Collections.emptyList();
        boolean tokenTruncated;
        List<BasicBlockRec> basicBlocks = new ArrayList<BasicBlockRec>();
        List<CfgEdge> cfgEdges = new ArrayList<CfgEdge>();
        List<CallRef> callRefs = new ArrayList<CallRef>();
        Map<String, Integer> stringRefs = new TreeMap<String, Integer>();
        Map<String, Integer> constantBuckets = new TreeMap<String, Integer>();
        long instructionCount;
        long callCount;
        long branchCount;
        long retCount;
        long stringRefCount;
        long constantCount;
    }

    private static class BasicBlockRec {
        int id;
        String start;
        String end;
        long size;
        BasicBlockRec(int id, String start, String end, long size) {
            this.id = id;
            this.start = start;
            this.end = end;
            this.size = size;
        }
    }

    private static class CfgEdge {
        int src;
        int dst;
        String type;
        CfgEdge(int src, int dst, String type) {
            this.src = src;
            this.dst = dst;
            this.type = type;
        }
    }

    private static class CallRef {
        String site;
        String target;
        String kind;
    }
}
