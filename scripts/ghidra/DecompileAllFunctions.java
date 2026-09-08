// DecompileAllFunctions.java -- Ghidra headless script
// Decompiles all non-thunk, non-external functions and writes JSON output.
// Usage: analyzeHeadless ... -postScript DecompileAllFunctions.java <output_path>
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.FileWriter;
import java.util.LinkedHashMap;
import java.util.Map;

public class DecompileAllFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outputPath = getScriptArgs()[0];
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        Map<String, String> functions = new LinkedHashMap<>();
        Map<String, String> signatures = new LinkedHashMap<>();

        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.isThunk() || func.isExternal()) continue;

            String name = func.getName();
            String addr = func.getEntryPoint().toString();
            String key = name + "@" + addr;

            DecompileResults res = decomp.decompileFunction(func, 30, monitor);
            if (res.getDecompiledFunction() != null) {
                functions.put(key, res.getDecompiledFunction().getC());
                signatures.put(key, res.getDecompiledFunction().getSignature());
            } else {
                functions.put(key, "// Decompilation failed: " + res.getErrorMessage());
            }
        }
        decomp.dispose();

        // Write JSON manually since Gson may not be available
        FileWriter writer = new FileWriter(outputPath);
        writer.write("{\n");
        writer.write("  \"program_name\": \"" + escapeJson(currentProgram.getName()) + "\",\n");
        writer.write("  \"language\": \"" + escapeJson(currentProgram.getLanguageID().toString()) + "\",\n");
        writer.write("  \"compiler\": \"" + escapeJson(currentProgram.getCompilerSpec().getCompilerSpecID().toString()) + "\",\n");
        writer.write("  \"functions\": {\n");
        int i = 0;
        for (Map.Entry<String, String> entry : functions.entrySet()) {
            if (i > 0) writer.write(",\n");
            writer.write("    \"" + escapeJson(entry.getKey()) + "\": \"" + escapeJson(entry.getValue()) + "\"");
            i++;
        }
        writer.write("\n  },\n");
        writer.write("  \"signatures\": {\n");
        i = 0;
        for (Map.Entry<String, String> entry : signatures.entrySet()) {
            if (i > 0) writer.write(",\n");
            writer.write("    \"" + escapeJson(entry.getKey()) + "\": \"" + escapeJson(entry.getValue()) + "\"");
            i++;
        }
        writer.write("\n  }\n");
        writer.write("}\n");
        writer.close();

        println("DecompileAllFunctions: wrote " + functions.size() + " functions to " + outputPath);
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }
}
