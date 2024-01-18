package ghidrarsp;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

public class OSTask implements StructConverter {

    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        Structure ty = new StructureDataType("OSTask", 0);
        ty.add(DWORD, "type", null);
        ty.add(DWORD, "flags", null);
        ty.add(DWORD, "uboot", null);
        ty.add(DWORD, "uboot_size", null);
        ty.add(DWORD, "ucode", null);
        ty.add(DWORD, "ucode_size", null);
        ty.add(DWORD, "udata", null);
        ty.add(DWORD, "udata_size", null);
        ty.add(DWORD, "stack", null);
        ty.add(DWORD, "stack_size", null);
        ty.add(DWORD, "outbuff", null);
        ty.add(DWORD, "outbuff_size", null);
        ty.add(DWORD, "data", null);
        ty.add(DWORD, "data_size", null);
        ty.add(DWORD, "yield", null);
        ty.add(DWORD, "yield_size", null);

        return ty;
    }

}
