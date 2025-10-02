// Headless post-analysis script for r2d2. Place in Ghidra script path.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;

public class R2D2Headless extends GhidraScript {
    @Override
    protected void run() throws Exception {
        println("[r2d2] R2D2Headless script executing");
        if (currentProgram == null) {
            println("[r2d2] No program loaded");
            return;
        }
        Listing listing = currentProgram.getListing();
        int functionCount = 0;
        for (Function function : listing.getFunctions(true)) {
            monitor.checkCanceled();
            functionCount++;
        }
        println("[r2d2] Total functions: " + functionCount);
    }
}
