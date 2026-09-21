/*
 * Parser for Windows icon-library (.icl) files -- and, more generally,
 * for the RT_ICON / RT_GROUP_ICON resources embedded in ANY Portable
 * Executable (PE32 or PE32+) image, since a modern .icl is simply a PE
 * DLL whose resource section holds nothing but icon groups (Windows
 * never actually runs its code; the "library" is just a resource
 * container by convention).
 *
 * Format background:
 *
 *   PE resource directory (the .rsrc section, walked via the data
 *   directory at index 2 of the Optional Header, NOT via section name --
 *   per the Microsoft PE/COFF spec you must not assume section names or
 *   positions):
 *
 *     IMAGE_RESOURCE_DIRECTORY (16 bytes)
 *       DWORD Characteristics
 *       DWORD TimeDateStamp
 *       WORD  MajorVersion
 *       WORD  MinorVersion
 *       WORD  NumberOfNamedEntries
 *       WORD  NumberOfIdEntries
 *       -- followed by (NumberOfNamedEntries + NumberOfIdEntries) entries:
 *
 *     IMAGE_RESOURCE_DIRECTORY_ENTRY (8 bytes)
 *       DWORD Name          -- high bit set: low 31 bits = RVA (relative to
 *                              the start of the resource section) to an
 *                              IMAGE_RESOURCE_DIR_STRING_U (name entry);
 *                              high bit clear: low 16 bits = numeric ID
 *       DWORD OffsetToData  -- high bit set: low 31 bits = offset (relative
 *                              to the start of the resource section) to a
 *                              nested IMAGE_RESOURCE_DIRECTORY (one more
 *                              level down); high bit clear: low 31 bits =
 *                              offset (relative to the start of the
 *                              resource section) to an
 *                              IMAGE_RESOURCE_DATA_ENTRY (leaf)
 *
 *   The resource directory is a fixed 3-level tree: Type -> Name/ID ->
 *   Language -> data entry. We want Type == RT_ICON (3) and
 *   Type == RT_GROUP_ICON (14).
 *
 *     IMAGE_RESOURCE_DATA_ENTRY (16 bytes)
 *       DWORD OffsetToData  -- an RVA (relative to image base), NOT
 *                              relative to the resource section
 *       DWORD Size
 *       DWORD CodePage
 *       DWORD Reserved
 *
 *   RVAs are converted to file offsets via the section table (each
 *   IMAGE_SECTION_HEADER gives VirtualAddress + PointerToRawData), never
 *   by assuming the RVA lands inside a section literally named ".rsrc".
 *
 *   Each RT_GROUP_ICON resource's data is a GRPICONDIR (a NEWHEADER in
 *   some references) -- structurally identical to an .ico file's own
 *   ICONDIR/ICONDIRENTRY header except each entry's last field is a
 *   16-bit RT_ICON resource ID (nID) instead of a 32-bit file offset:
 *
 *     GRPICONDIR (6 bytes header)
 *       WORD idReserved   -- must be 0
 *       WORD idType       -- 1 = icon
 *       WORD idCount      -- number of images in this group
 *     GRPICONDIRENTRY (14 bytes each, immediately follows, no padding)
 *       BYTE  bWidth
 *       BYTE  bHeight
 *       BYTE  bColorCount
 *       BYTE  bReserved
 *       WORD  wPlanes
 *       WORD  wBitCount
 *       DWORD dwBytesInRes  -- size of the matching RT_ICON resource
 *       WORD  nID           -- numeric ID of the matching RT_ICON resource
 *
 *   To reconstruct a standalone .ico: emit an ICONDIR (idReserved=0,
 *   idType=1, idCount=N) followed by N 16-byte ICONDIRENTRY records (the
 *   same first 8 bytes as GRPICONDIRENTRY, then a 4-byte dwImageOffset
 *   computed as we lay out the file), followed by the N images' raw
 *   bytes copied verbatim from each matching RT_ICON resource (an
 *   ICONIMAGE: either a legacy BITMAPINFOHEADER+XOR/AND bitmap, or --
 *   Vista and later, for large/high-color icons -- a raw embedded PNG;
 *   either way we never need to interpret the pixels, only copy bytes).
 *
 * Ground truth for this parser was built by compiling a real PE32 and a
 * real PE32+ DLL with `x86_64-w64-mingw32-gcc`/`i686-w64-mingw32-gcc` and
 * icon resources added via `windres`, then independently cross-checked
 * with icoutils' `wrestool`/`icotool` (a real, separately-maintained
 * implementation) -- see icl-parser.node-test.js.
 *
 * Legacy 16-bit "NE" (New Executable, Windows 3.x-era) .icl files use a
 * completely different resource table format and are explicitly OUT OF
 * SCOPE for this version: we detect that header and fail with a clear,
 * honest message rather than guessing.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.IclParser = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  class IclParseError extends Error {}

  const RT_ICON = 3;
  const RT_GROUP_ICON = 14;
  const IMAGE_DIRECTORY_ENTRY_RESOURCE = 2;

  // -----------------------------------------------------------------
  // DOS/PE/COFF header + section table
  // -----------------------------------------------------------------

  function readCoffAndSections(view) {
    if (view.byteLength < 0x40) throw new IclParseError('File is too small to be a PE image.');
    if (view.getUint8(0) !== 0x4d || view.getUint8(1) !== 0x5a) {
      throw new IclParseError('Not a PE/NE file: missing the "MZ" DOS header signature.');
    }
    const e_lfanew = view.getUint32(0x3c, true);
    if (e_lfanew + 24 > view.byteLength) {
      throw new IclParseError('DOS header points past the end of the file.');
    }
    const sig0 = view.getUint8(e_lfanew);
    const sig1 = view.getUint8(e_lfanew + 1);
    if (sig0 === 0x4e && sig1 === 0x45) {
      // "NE" -- 16-bit New Executable (Windows 3.x-era icon libraries).
      throw new IclParseError(
        'This is a legacy 16-bit "NE" icon library (Windows 3.x era). ' +
        'This tool currently supports modern 32-/64-bit PE-format .icl files only.'
      );
    }
    if (sig0 !== 0x50 || sig1 !== 0x45 || view.getUint8(e_lfanew + 2) !== 0 || view.getUint8(e_lfanew + 3) !== 0) {
      throw new IclParseError('Not a recognized PE file: missing the "PE\\0\\0" signature.');
    }
    const coffOff = e_lfanew + 4;
    const numberOfSections = view.getUint16(coffOff + 2, true);
    const sizeOfOptionalHeader = view.getUint16(coffOff + 16, true);
    const optHdrOff = coffOff + 20;
    if (sizeOfOptionalHeader < 2) throw new IclParseError('PE file has no Optional Header.');
    const magic = view.getUint16(optHdrOff, true);
    let architecture;
    if (magic === 0x10b) architecture = 'PE32';
    else if (magic === 0x20b) architecture = 'PE32+';
    else throw new IclParseError(`Unrecognized Optional Header magic 0x${magic.toString(16)}.`);

    const numRvaOff = architecture === 'PE32+' ? optHdrOff + 108 : optHdrOff + 92;
    const numRvaAndSizes = view.getUint32(numRvaOff, true);
    const dataDirOff = numRvaOff + 4;
    if (numRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_RESOURCE) {
      throw new IclParseError('This PE file has no resource directory (no icons embedded).');
    }
    const resDirEntryOff = dataDirOff + 8 * IMAGE_DIRECTORY_ENTRY_RESOURCE;
    const resRva = view.getUint32(resDirEntryOff, true);
    const resSize = view.getUint32(resDirEntryOff + 4, true);
    if (!resSize) throw new IclParseError('This PE file has no resource directory (no icons embedded).');

    const sectionTableOff = optHdrOff + sizeOfOptionalHeader;
    const sections = [];
    for (let i = 0; i < numberOfSections; i++) {
      const off = sectionTableOff + i * 40;
      if (off + 40 > view.byteLength) throw new IclParseError('Section table runs past the end of the file.');
      let name = '';
      for (let j = 0; j < 8; j++) {
        const c = view.getUint8(off + j);
        if (c === 0) break;
        name += String.fromCharCode(c);
      }
      sections.push({
        name,
        virtualSize: view.getUint32(off + 8, true),
        virtualAddress: view.getUint32(off + 12, true),
        sizeOfRawData: view.getUint32(off + 16, true),
        pointerToRawData: view.getUint32(off + 20, true),
      });
    }

    return { architecture, resRva, resSize, sections };
  }

  function rvaToFileOffset(sections, rva) {
    for (const s of sections) {
      const size = Math.max(s.virtualSize, s.sizeOfRawData);
      if (rva >= s.virtualAddress && rva < s.virtualAddress + size) {
        return rva - s.virtualAddress + s.pointerToRawData;
      }
    }
    throw new IclParseError(`RVA 0x${rva.toString(16)} does not fall inside any section.`);
  }

  // -----------------------------------------------------------------
  // Resource directory walk
  // -----------------------------------------------------------------

  // resBase = file offset of the start of the resource directory (i.e.
  // the file offset corresponding to resRva). All offsets inside the
  // resource directory tree are relative to resBase EXCEPT the leaf
  // IMAGE_RESOURCE_DATA_ENTRY's own OffsetToData, which is an RVA
  // relative to the image base (must go through rvaToFileOffset).
  function readResourceDirectory(view, base, resBase) {
    if (base + 16 > view.byteLength) throw new IclParseError('Resource directory runs past the end of the file.');
    const numNamed = view.getUint16(base + 12, true);
    const numId = view.getUint16(base + 14, true);
    const total = numNamed + numId;
    const entries = [];
    for (let i = 0; i < total; i++) {
      const eOff = base + 16 + i * 8;
      if (eOff + 8 > view.byteLength) throw new IclParseError('Resource directory entry runs past the end of the file.');
      const nameField = view.getUint32(eOff, true);
      const offsetField = view.getUint32(eOff + 4, true);
      const isNamed = (nameField & 0x80000000) !== 0;
      let id = null, name = null;
      if (isNamed) {
        const strOff = resBase + (nameField & 0x7fffffff);
        const len = view.getUint16(strOff, true);
        let s = '';
        for (let j = 0; j < len; j++) s += String.fromCharCode(view.getUint16(strOff + 2 + j * 2, true));
        name = s;
      } else {
        id = nameField & 0xffff;
      }
      const isSubdir = (offsetField & 0x80000000) !== 0;
      const target = resBase + (offsetField & 0x7fffffff);
      entries.push({ id, name, isSubdir, target });
    }
    return entries;
  }

  // Parses the whole ICL/PE resource tree and returns a map of every
  // RT_ICON resource (by numeric id) to its raw bytes, plus a list of
  // every RT_GROUP_ICON resource (numeric id or string name) with its
  // raw GRPICONDIR bytes.
  function collectIconResources(view, coff) {
    const resBase = rvaToFileOffset(coff.sections, coff.resRva);
    const typeEntries = readResourceDirectory(view, resBase, resBase);

    const icons = new Map(); // id -> {offset, size}
    const groups = []; // {id, name, offset, size}

    for (const typeEntry of typeEntries) {
      if (typeEntry.id !== RT_ICON && typeEntry.id !== RT_GROUP_ICON) continue;
      if (!typeEntry.isSubdir) continue;
      const nameEntries = readResourceDirectory(view, typeEntry.target, resBase);
      for (const nameEntry of nameEntries) {
        if (!nameEntry.isSubdir) continue;
        const langEntries = readResourceDirectory(view, nameEntry.target, resBase);
        for (const langEntry of langEntries) {
          if (langEntry.isSubdir) continue; // shouldn't happen at this depth
          const dataEntryOff = langEntry.target;
          if (dataEntryOff + 16 > view.byteLength) throw new IclParseError('Resource data entry runs past the end of the file.');
          const dataRva = view.getUint32(dataEntryOff, true);
          const dataSize = view.getUint32(dataEntryOff + 4, true);
          const fileOff = rvaToFileOffset(coff.sections, dataRva);
          if (fileOff + dataSize > view.byteLength) throw new IclParseError('Resource data runs past the end of the file.');
          if (typeEntry.id === RT_ICON) {
            icons.set(nameEntry.id, { offset: fileOff, size: dataSize });
          } else {
            groups.push({ id: nameEntry.id, name: nameEntry.name, offset: fileOff, size: dataSize });
          }
          break; // only need the first language variant
        }
      }
    }
    return { icons, groups };
  }

  // -----------------------------------------------------------------
  // GRPICONDIR -> standalone .ico reconstruction
  // -----------------------------------------------------------------

  function buildIcoFromGroup(view, bytes, group, icons) {
    const g = group.offset;
    const idReserved = view.getUint16(g, true);
    const idType = view.getUint16(g + 2, true);
    const idCount = view.getUint16(g + 4, true);
    if (idReserved !== 0 || (idType !== 1 && idType !== 2)) {
      throw new IclParseError(`Malformed GRPICONDIR for group "${group.name || group.id}".`);
    }
    const entries = [];
    for (let i = 0; i < idCount; i++) {
      const eOff = g + 6 + i * 14;
      if (eOff + 14 > group.offset + group.size) throw new IclParseError('GRPICONDIRENTRY runs past its resource.');
      const bWidth = view.getUint8(eOff);
      const bHeight = view.getUint8(eOff + 1);
      const bColorCount = view.getUint8(eOff + 2);
      const wPlanes = view.getUint16(eOff + 4, true);
      const wBitCount = view.getUint16(eOff + 6, true);
      const dwBytesInRes = view.getUint32(eOff + 8, true);
      const nID = view.getUint16(eOff + 12, true);
      const iconRes = icons.get(nID);
      if (!iconRes) throw new IclParseError(`Group "${group.name || group.id}" references RT_ICON id ${nID}, which was not found.`);
      entries.push({ bWidth, bHeight, bColorCount, wPlanes, wBitCount, dwBytesInRes, iconRes });
    }

    const headerSize = 6 + 16 * idCount;
    let dataSize = 0;
    for (const e of entries) dataSize += e.dwBytesInRes;
    const out = new Uint8Array(headerSize + dataSize);
    const ov = new DataView(out.buffer);
    ov.setUint16(0, 0, true);
    ov.setUint16(2, idType, true);
    ov.setUint16(4, idCount, true);
    let cursor = headerSize;
    for (let i = 0; i < idCount; i++) {
      const e = entries[i];
      const eOff = 6 + i * 16;
      out[eOff] = e.bWidth;
      out[eOff + 1] = e.bHeight;
      out[eOff + 2] = e.bColorCount;
      out[eOff + 3] = 0;
      ov.setUint16(eOff + 4, e.wPlanes, true);
      ov.setUint16(eOff + 6, e.wBitCount, true);
      ov.setUint32(eOff + 8, e.dwBytesInRes, true);
      ov.setUint32(eOff + 12, cursor, true);
      out.set(bytes.subarray(e.iconRes.offset, e.iconRes.offset + e.dwBytesInRes), cursor);
      cursor += e.dwBytesInRes;
    }
    return out;
  }

  function describeGroup(view, group) {
    const idCount = view.getUint16(group.offset + 4, true);
    const sizes = [];
    for (let i = 0; i < idCount; i++) {
      const eOff = group.offset + 6 + i * 14;
      sizes.push({
        width: view.getUint8(eOff) || 256,
        height: view.getUint8(eOff + 1) || 256,
        bitCount: view.getUint16(eOff + 6, true),
      });
    }
    return sizes;
  }

  function parseIclBuffer(buffer) {
    const bytes = new Uint8Array(buffer);
    const view = new DataView(buffer);
    const coff = readCoffAndSections(view);
    const { icons, groups } = collectIconResources(view, coff);
    if (!groups.length) {
      throw new IclParseError('No icon groups (RT_GROUP_ICON) found in this file. It may be a plain EXE/DLL with no icons, or an .icl in an unsupported layout.');
    }
    groups.sort((a, b) => {
      const ka = a.name != null ? a.name : String(a.id).padStart(10, '0');
      const kb = b.name != null ? b.name : String(b.id).padStart(10, '0');
      return ka.localeCompare(kb);
    });
    const result = {
      architecture: coff.architecture,
      fileSize: bytes.length,
      groupCount: groups.length,
      totalIconImages: 0,
      groups: [],
    };
    for (const group of groups) {
      const sizes = describeGroup(view, group);
      const icoBytes = buildIcoFromGroup(view, bytes, group, icons);
      result.totalIconImages += sizes.length;
      result.groups.push({
        label: group.name != null ? group.name : `#${group.id}`,
        sizes,
        icoBytes,
      });
    }
    return result;
  }

  return { IclParseError, parseIclBuffer, readCoffAndSections, rvaToFileOffset };
});
