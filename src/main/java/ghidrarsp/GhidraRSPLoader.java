/* ###
* IP: GHIDRA
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package ghidrarsp;

import java.io.IOException;
import java.util.*;
import java.io.FileInputStream;
import java.io.File;

import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import ghidra.app.util.opinion.Loader;

/**
* TODO: Provide class-level documentation that describes what this loader does.
*/
public class GhidraRSPLoader extends AbstractProgramWrapperLoader {

    private static String OPTION_IS_BOOT = "Is Boot";

    @Override
    public String getName() {
        return "Nintendo 64 RSP loader";
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("RSP:BE:32:default", "default"), true));

        return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
    Program program, TaskMonitor monitor, MessageLog log)
    throws CancelledException, IOException {

        FlatProgramAPI api = new FlatProgramAPI(program);

        int dmemEnd = 0;
        while (true)
        {
            GhidraFileChooser chooser = new GhidraFileChooser(null);
            chooser.setTitle("Choose a ucode rodata file (the content of DMEM)");
            File f = chooser.getSelectedFile();
            if (f == null)
                break;

            if (!f.exists() || f.isDirectory())
                continue;

            byte[] bytes = new byte[(int)f.length()];
            dmemEnd = bytes.length;
            var fileReader = new FileInputStream(f.getPath());
            fileReader.read(bytes);
            fileReader.close();
            try {
                api.createMemoryBlock("dmem", api.toAddr(0), bytes,false).setPermissions(true, true, false);
            } catch (Exception e) {
                e.printStackTrace();
                throw new CancelledException();
            }
            break;
        }

        boolean isBoot = OptionUtils.getBooleanOptionValue(OPTION_IS_BOOT, options, false);

        byte[] imem = provider.readBytes(0, provider.length());
        try {
            api.createMemoryBlock("imem", api.toAddr(isBoot ? 0x1000 : 0x1080), imem, false).setPermissions(true, false, true);
            program.getMemory().createUninitializedBlock("dmem.uninit", api.toAddr(dmemEnd), 0x1000 - dmemEnd, false).setPermissions(true, true, false);
        } catch (Exception e) {
            e.printStackTrace();
            throw new CancelledException();
        }

        try {
            api.createData(api.toAddr(0xFC0), new OSTask().toDataType());
        } catch (CodeUnitInsertionException | DuplicateNameException | IOException e) {
            e.printStackTrace();
            throw new CancelledException();
        }

    }

    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
    DomainObject domainObject, boolean isLoadIntoProgram) {
        List<Option> list =
        super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

        list.add(new Option(OPTION_IS_BOOT, false, Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-isBoot"));

        return list;
    }

    @Override
    public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

        // TODO: If this loader has custom options, validate them here.  Not all options require
        // validation.

        return super.validateOptions(provider, loadSpec, options, program);
    }
}
