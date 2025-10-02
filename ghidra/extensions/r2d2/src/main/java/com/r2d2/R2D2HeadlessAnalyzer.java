package com.r2d2;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.exception.CancelledException;

public class R2D2HeadlessAnalyzer extends GhidraScript {
    @Override
    protected void run() throws Exception {
        println("[r2d2] Headless analysis starting...");
        var program = getCurrentProgram();
        if (program == null) {
            println("[r2d2] No program loaded");
            return;
        }

        Listing listing = program.getListing();
        ReferenceManager refManager = program.getReferenceManager();

        int functionCount = 0;
        for (Function function : listing.getFunctions(true)) {
            monitor.checkCanceled();
            functionCount++;
        }

        println(String.format("[r2d2] Functions discovered: %d", functionCount));
        println(String.format("[r2d2] External references: %d", refManager.getExternalEntryPointIterator().hasNext() ? 1 : 0));

        println("[r2d2] Analysis complete");
    }
}
