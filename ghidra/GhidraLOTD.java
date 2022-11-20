import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.app.decompiler.DecompileResults;
import java.util.Iterator;
import java.util.ArrayList;
import java.lang.Process;
import java.lang.ProcessBuilder;
import java.io.OutputStream;
import java.io.IOException;
import java.io.File;
import java.nio.file.Path;

public class GhidraLOTD extends GhidraScript {
    public Process startDwarfProducer() throws IOException {
        Path finfo = sourceFile.getFile(true).toPath();
        String dwarfp_path = finfo.resolveSibling("ghidra-lotd").toAbsolutePath().toString();
        File output_path = finfo.resolveSibling("dwarf.elf").toAbsolutePath().toFile(); 
        println(dwarfp_path);
        ProcessBuilder pb = new ProcessBuilder(dwarfp_path);
        pb.redirectOutput(output_path);
        return pb.start();
    }
    public Address getEntryPoint() {
        ArrayList<Address> entryPoints = new ArrayList<Address>();
        Iterator<Address> iterAddresses =
            getCurrentProgram().getSymbolTable().getExternalEntryPointIterator();
        iterAddresses.forEachRemaining(entryPoints::add);
        if (entryPoints.size() == 0) {
            throw new IllegalStateException(
                "No external entry point found. Try this python one-liner.\n"
                + "currentProgram.symbolTable.addExternalEntryPoint(currentProgram.addressFactory.getAddress('[address]'))\n"
            );
        } else if (entryPoints.size() > 1) {
            // Choose between entry points.
        }
        return entryPoints.get(0);
    }
    public void decompileFunction(DecompInterface ifc, Function fn, OutputStream stream) throws IOException {
        DecompileResults res = ifc.decompileFunction(fn, 0, monitor);
        ArrayList<ClangLine> lines = DecompilerUtils.toLines(res.getCCodeMarkup());
        for (ClangLine l: lines) {
            println(l.toString());
        }
    }
    public void run() throws Exception {
        println("Hello, World!");
        Address entryPoint = getEntryPoint();
        println("Entry Point: " + entryPoint.toString());
        FunctionManager fnManager = getCurrentProgram().getFunctionManager();
        Function entry = fnManager.getFunctionContaining(entryPoint);
        FunctionIterator fnIter = fnManager.getFunctions(false);
        DecompInterface ifc = new DecompInterface();
        ifc.toggleSyntaxTree(true);
        ifc.toggleCCode(true);
        ifc.openProgram(getCurrentProgram());
        Process dwarfp = startDwarfProducer();
        try (OutputStream outstream = dwarfp.getOutputStream()) {
            decompileFunction(ifc, entry, outstream);
        }
    }
}
