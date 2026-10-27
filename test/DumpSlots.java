// Decode the first instruction of every fixed-size slot of the current program's first block
// with the language's default context (optionally overriding context fields).
// Each slot is parsed without Ghidra's instruction prototype cache (SleighLanguage.parse reuses a
// cached prototype whose hash matches, and different encodings occasionally hash alike); slots
// where the cached parse differs are listed in <outfile>.collisions.
// Prints "<offset-hex> <len> <text>" per slot, "<offset> 0 BAD" when the language rejects it.
// Script args: <slot> <outfile> [ctxfield=value ...]
//@category Testing

import java.io.PrintStream;
import java.math.BigInteger;

import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.processors.sleigh.ContextCache;
import ghidra.app.plugin.processors.sleigh.SleighInstructionPrototype;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.ProcessorContextImpl;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryBlock;

public class DumpSlots extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		int slot = Integer.decode(args[0]);
		PrintStream out = new PrintStream(args[1]);
		Language lang = currentProgram.getLanguage();
		ProcessorContextImpl ctx = new ProcessorContextImpl(lang);
		Register cr = lang.getContextBaseRegister();
		if (cr != null && cr != Register.NO_CONTEXT) {
			ctx.setRegisterValue(currentProgram.getProgramContext().getDefaultDisassemblyContext());
		}
		for (int i = 2; i < args.length; i++) {
			String[] kv = args[i].split("=");
			ctx.setValue(lang.getRegister(kv[0]), new BigInteger(kv[1]));
		}
		// the language's own context cache (a private field) for the uncached parse
		java.lang.reflect.Field ccf = SleighLanguage.class.getDeclaredField("contextcache");
		ccf.setAccessible(true);
		ContextCache cc = (ContextCache) ccf.get(lang);
		java.lang.reflect.Method cacheInfo = SleighInstructionPrototype.class.getDeclaredMethod(
			"cacheInfo", MemBuffer.class, ghidra.program.model.lang.ProcessorContextView.class, boolean.class);
		cacheInfo.setAccessible(true);
		PrintStream coll = new PrintStream(args[1] + ".collisions");
		MemoryBlock block = currentProgram.getMemory().getBlocks()[0];
		Address base = block.getStart();
		long size = block.getSize();
		for (long off = 0; off + slot <= size; off += slot) {
			Address a = base.add(off);
			String text;
			int n;
			try {
				MemBuffer buf = new DumbMemBufferImpl(currentProgram.getMemory(), a);
				SleighInstructionPrototype proto =
					new SleighInstructionPrototype((SleighLanguage) lang, buf, ctx, cc, false, null);
				cacheInfo.invoke(proto, buf, ctx, true);
				PseudoInstruction pi = new PseudoInstruction(currentProgram, a, proto, buf, ctx);
				text = pi.toString();
				n = pi.getLength();
				try {
					InstructionPrototype cached = lang.parse(buf, ctx, false);
					String ct = new PseudoInstruction(currentProgram, a, cached, buf, ctx).toString();
					if (!ct.equals(text)) {
						coll.printf("%08x cached: %s / uncached: %s%n", off, ct, text);
					}
				}
				catch (Exception e) {
					coll.printf("%08x cached parse failed / uncached: %s%n", off, text);
				}
			}
			catch (Exception e) {
				text = "BAD";
				n = 0;
				if (off == 0) {
					printerr("first slot: " + e);
				}
			}
			out.printf("%08x %d %s%n", off, n, text);
		}
		out.close();
		coll.close();
	}
}
