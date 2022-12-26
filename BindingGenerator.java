// Generates C bindings for an executable's data types and symbols.
// @author codeshaunted
// @category Symbol

import java.io.File;
import java.io.FileWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypeWriter;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.TaskMonitor;

public class BindingGenerator extends GhidraScript {
	
	public String buildArgumentList(ParameterDefinition[] arguments) {
		if (arguments.length == 0) return "void"; // Return "void" if no arguments
		
		String parameterList = "";

		for (int i = 0; i < arguments.length; i++) {
			parameterList += arguments[i].getDataType().getName() + " " + arguments[i].getName();

			if (i == arguments.length - 1) break; // Don't add comma and space to last argument
			
			parameterList += ", ";
		}
		
		return parameterList;
	}

	public void run() throws Exception {
		// Setup variables
		Program currentProgram = getCurrentProgram();
		String programName = currentProgram.getName();
		DataTypeManager dataTypeManager = currentProgram.getDataTypeManager();
		SymbolTable symbolTable = currentProgram.getSymbolTable();
		FunctionManager functionManager = currentProgram.getFunctionManager();
		
		// Prompt for output directory
		File outputDirectory = askDirectory("Output Directory", "Choose Output Directory");

		// Setup FileWriter and DataTypeWriter
		FileWriter headerWriter = new FileWriter(new File(outputDirectory, programName + ".h"));
		DataTypeWriter dataTypeWriter = new DataTypeWriter(dataTypeManager, headerWriter);
		
		// Write types to header file with DataTypeWriter
		dataTypeWriter.write(dataTypeManager, TaskMonitor.DUMMY);
		
		for (Symbol symbol : symbolTable.getAllSymbols(false)) {
			// Don't allow externals
			// TODO: Maybe fix to allow for externals?
			if (symbol.isExternal()) continue;
			
			if (symbol.getSymbolType() == SymbolType.LABEL) {
				Data symbolData = DataUtilities.getDataAtAddress(currentProgram, symbol.getAddress());
			
				// Filter out null references (typically switch cases)
				// TODO: Find out why these are null references
				if (symbolData == null) continue;
			
				// Gather label data
				String dataType = symbolData.getDataType().getName();
				String name = symbol.getName(true);
				String address = "0x" + symbol.getAddress();
			
				// Build label data into definition and write to file
				String labelDefinition = String.format("%s* %s = (%s*)%s;\n", dataType, name, dataType, address);
				headerWriter.write(labelDefinition);
			} else if (symbol.getSymbolType() == SymbolType.FUNCTION) {
				Function function = functionManager.getFunctionAt(symbol.getAddress());
				
				// Gather function data
				String callingConvention = function.getCallingConventionName();
				String returnType = function.getReturnType().getName();
				String name = function.getName();
				String argumentList = buildArgumentList(function.getSignature().getArguments());
				String address = "0x" + symbol.getAddress();
				
				// Build function data into definition and write to file
				String functionDefinition = String.format("%s (%s *%s)(%s) = (%s (%s *)(%s))%s;\n", returnType, callingConvention, name, argumentList, returnType, callingConvention, argumentList, address);
				headerWriter.write(functionDefinition);
			}
		}
		
		// Close FileWriter
		headerWriter.close();
	}

}
