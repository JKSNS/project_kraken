// ExtractCallGraph.java -- Ghidra headless script
// Extracts function call graph and writes JSON output.
// Usage: analyzeHeadless ... -postScript ExtractCallGraph.java <output_path>
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.FileWriter;
import java.util.*;

public class ExtractCallGraph extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outputPath = getScriptArgs()[0];

        Map<String, List<String>> callGraph = new LinkedHashMap<>();
        List<String> strings = new ArrayList<>();

        // Build call graph
        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.isThunk() || func.isExternal()) continue;

            String caller = func.getName() + "@" + func.getEntryPoint();
            List<String> callees = new ArrayList<>();
            Set<Function> called = func.getCalledFunctions(monitor);
            for (Function callee : called) {
                callees.add(callee.getName() + "@" + callee.getEntryPoint());
            }
            callGraph.put(caller, callees);
        }

        // Extract defined strings
        var dataIter = currentProgram.getListing().getDefinedData(true);
        while (dataIter.hasNext()) {
            var data = dataIter.next();
            if (data.getDataType().getName().toLowerCase().contains("string")) {
                Object val = data.getValue();
                if (val != null) {
                    strings.add(val.toString());
                }
            }
        }

        // Write JSON manually
        FileWriter writer = new FileWriter(outputPath);
        writer.write("{\n  \"call_graph\": {\n");
        int i = 0;
        for (Map.Entry<String, List<String>> entry : callGraph.entrySet()) {
            if (i > 0) writer.write(",\n");
            writer.write("    \"" + escapeJson(entry.getKey()) + "\": [");
            for (int j = 0; j < entry.getValue().size(); j++) {
                if (j > 0) writer.write(", ");
                writer.write("\"" + escapeJson(entry.getValue().get(j)) + "\"");
            }
            writer.write("]");
            i++;
        }
        writer.write("\n  },\n  \"strings\": [\n");
        for (int j = 0; j < strings.size(); j++) {
            if (j > 0) writer.write(",\n");
            writer.write("    \"" + escapeJson(strings.get(j)) + "\"");
        }
        writer.write("\n  ]\n}\n");
        writer.close();

        println("ExtractCallGraph: wrote " + callGraph.size() + " nodes, " + strings.size() + " strings to " + outputPath);
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }
}
