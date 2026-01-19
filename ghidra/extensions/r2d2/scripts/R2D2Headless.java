// Headless post-analysis script for r2d2.
// Outputs JSON with functions, strings, and decompiled code to a file.

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.util.exception.CancelledException;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class R2D2Headless extends GhidraScript {
    
    private static final int MAX_FUNCTIONS = 200;
    private static final int MAX_DECOMPILE = 50;
    private static final int MAX_STRINGS = 500;
    
    @Override
    protected void run() throws Exception {
        println("[r2d2] R2D2Headless script executing");
        
        if (currentProgram == null) {
            println("[r2d2] ERROR: No program loaded");
            return;
        }
        
        String programName = currentProgram.getName();
        println("[r2d2] Analyzing: " + programName);
        
        // Output file path - use env var or default location
        String outputPath = System.getenv("R2D2_OUTPUT");
        if (outputPath == null || outputPath.isEmpty()) {
            File programFile = getProgramFile();
            if (programFile != null) {
                outputPath = programFile.getParentFile().getAbsolutePath() + 
                             "/" + programName + "_r2d2.json";
            } else {
                outputPath = "/tmp/" + programName + "_r2d2.json";
            }
        }
        
        println("[r2d2] Output: " + outputPath);
        
        // Collect data
        List<String[]> functions = collectFunctions();
        List<String[]> strings = collectStrings();
        List<String[]> decompiled = decompileFunctions(functions);
        
        // Write JSON output
        writeJsonOutput(outputPath, functions, strings, decompiled);
        
        println("[r2d2] Analysis complete. Functions: " + functions.size() + 
                ", Strings: " + strings.size() + ", Decompiled: " + decompiled.size());
    }
    
    private List<String[]> collectFunctions() throws CancelledException {
        List<String[]> functions = new ArrayList<>();
        Listing listing = currentProgram.getListing();
        FunctionIterator iter = listing.getFunctions(true);
        
        int count = 0;
        while (iter.hasNext() && count < MAX_FUNCTIONS) {
            monitor.checkCancelled();
            Function func = iter.next();
            
            String name = func.getName();
            String address = func.getEntryPoint().toString();
            String signature = func.getPrototypeString(false, false);
            String isThunk = func.isThunk() ? "true" : "false";
            String size = String.valueOf(func.getBody().getNumAddresses());
            
            functions.add(new String[]{name, address, signature, isThunk, size});
            count++;
        }
        
        println("[r2d2] Collected " + count + " functions");
        return functions;
    }
    
    private List<String[]> collectStrings() throws CancelledException {
        List<String[]> strings = new ArrayList<>();
        Listing listing = currentProgram.getListing();
        
        // Iterate over defined data looking for strings
        Iterator<Data> iter = listing.getDefinedData(true);
        int count = 0;
        
        while (iter.hasNext() && count < MAX_STRINGS) {
            monitor.checkCancelled();
            Data data = iter.next();
            
            if (data.hasStringValue()) {
                try {
                    Object value = data.getValue();
                    if (value != null) {
                        String strValue = value.toString();
                        if (strValue.length() >= 4 && strValue.length() <= 2000) {
                            String address = data.getAddress().toString();
                            strings.add(new String[]{address, escapeJson(strValue)});
                            count++;
                        }
                    }
                } catch (Exception e) {
                    // Skip problematic strings
                }
            }
        }
        
        println("[r2d2] Collected " + count + " strings");
        return strings;
    }
    
    private List<String[]> decompileFunctions(List<String[]> functions) throws CancelledException {
        List<String[]> decompiled = new ArrayList<>();
        
        // Initialize decompiler
        DecompInterface decomp = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decomp.setOptions(options);
        
        if (!decomp.openProgram(currentProgram)) {
            println("[r2d2] WARNING: Could not initialize decompiler");
            return decompiled;
        }
        
        Listing listing = currentProgram.getListing();
        int count = 0;
        
        for (String[] funcInfo : functions) {
            if (count >= MAX_DECOMPILE) break;
            
            monitor.checkCancelled();
            String name = funcInfo[0];
            String addrStr = funcInfo[1];
            String isThunk = funcInfo[3];
            
            // Skip thunks
            if ("true".equals(isThunk)) continue;
            
            try {
                Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
                Function func = listing.getFunctionAt(addr);
                
                if (func != null && !func.isThunk()) {
                    DecompileResults results = decomp.decompileFunction(func, 30, monitor);
                    
                    if (results != null && results.decompileCompleted()) {
                        String code = results.getDecompiledFunction().getC();
                        if (code != null && !code.isEmpty()) {
                            decompiled.add(new String[]{name, addrStr, escapeJson(code)});
                            count++;
                        }
                    }
                }
            } catch (Exception e) {
                // Skip functions that fail to decompile
                println("[r2d2] Failed to decompile " + name + ": " + e.getMessage());
            }
        }
        
        decomp.dispose();
        println("[r2d2] Decompiled " + count + " functions");
        return decompiled;
    }
    
    private void writeJsonOutput(String outputPath, List<String[]> functions, 
                                  List<String[]> strings, List<String[]> decompiled) throws Exception {
        PrintWriter writer = new PrintWriter(new FileWriter(outputPath));
        
        writer.println("{");
        
        // Write program info
        writer.println("  \"program\": {");
        writer.println("    \"name\": \"" + escapeJson(currentProgram.getName()) + "\",");
        writer.println("    \"language\": \"" + currentProgram.getLanguageID().toString() + "\",");
        writer.println("    \"compiler\": \"" + currentProgram.getCompilerSpec().getCompilerSpecID().toString() + "\",");
        writer.println("    \"image_base\": \"" + currentProgram.getImageBase().toString() + "\"");
        writer.println("  },");
        
        // Write functions
        writer.println("  \"functions\": [");
        for (int i = 0; i < functions.size(); i++) {
            String[] f = functions.get(i);
            writer.print("    {\"name\": \"" + escapeJson(f[0]) + "\", ");
            writer.print("\"address\": \"" + f[1] + "\", ");
            writer.print("\"signature\": \"" + escapeJson(f[2]) + "\", ");
            writer.print("\"is_thunk\": " + f[3] + ", ");
            writer.print("\"size\": " + f[4] + "}");
            if (i < functions.size() - 1) writer.println(",");
            else writer.println();
        }
        writer.println("  ],");
        
        // Write strings
        writer.println("  \"strings\": [");
        for (int i = 0; i < strings.size(); i++) {
            String[] s = strings.get(i);
            writer.print("    {\"address\": \"" + s[0] + "\", \"value\": \"" + s[1] + "\"}");
            if (i < strings.size() - 1) writer.println(",");
            else writer.println();
        }
        writer.println("  ],");
        
        // Write decompiled code
        writer.println("  \"decompiled\": [");
        for (int i = 0; i < decompiled.size(); i++) {
            String[] d = decompiled.get(i);
            writer.print("    {\"name\": \"" + escapeJson(d[0]) + "\", ");
            writer.print("\"address\": \"" + d[1] + "\", ");
            writer.print("\"code\": \"" + d[2] + "\"}");
            if (i < decompiled.size() - 1) writer.println(",");
            else writer.println();
        }
        writer.println("  ]");
        
        writer.println("}");
        writer.close();
        
        println("[r2d2] Wrote JSON to: " + outputPath);
    }
    
    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
