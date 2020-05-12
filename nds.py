import math
import struct
import idaapi
import idc
import ida_bytes
import ida_netnode
import ida_segment

def shortBytesRepr(data, maxLen=None):
    """
    Like bytes.__repr__(), but will truncate large amounts of data.
    Will also take advantage of octal encoding to make the output more
    compact.
    """
    if maxLen is None:
        maxLen = 0x20

    dataTrunc = data[:maxLen]
    r = ["b'"]
    for i, b in enumerate(data):
        # We have to be careful to avoid shortening e.g. b'\x01\x31' into b'\11',
        # so we don't shorten if the following byte is an ASCII digit
        if b < 8 and (i == len(data) - 1 or data[i + 1] not in range(0x30, 0x3A)):
            r.append('\\' + b)
        else:
            r.append(repr(b.to_bytes(1, 'big'))[2:-1])
    r.append("'")

    final = ''.join(r)

    if len(data) > maxLen:
        return final + '...'
    else:
        return final

class Folder:
    """
    A single folder within a filename table, or an entire filename
    table.
    """
    def __init__(self, folders=None, files=None, firstID=0):
        if folders is not None:
            self.folders = folders
        else:
            self.folders = []
        if files is not None:
            self.files = files
        else:
            self.files = []
        self.firstID = firstID


    def __iter__(self):
        raise ValueError('Sorry, a Folder is not iterable.')


    def __getitem__(self, key):
        """
        Convenience function:
        - for an integer key, calls filenameOf()
        - for a string key:
            - calls idOf() if key refers to a file, or
            - calls subfolder() if key refers to a directory.
        """
        if isinstance(key, int):
            fn = self.filenameOf(key)
            if fn is not None:
                return fn
        elif isinstance(key, str):
            fileID = self.idOf(key)
            if fileID is None:
                sbf = self.subfolder(key)
                if sbf is not None:
                    return sbf
            else:
                return fileID
        else:
            raise TypeError('Folders can only convert between strings'
                            ' and ints, not "{type(key)}".')
        raise KeyError('Unknown key: {key}')


    def __contains__(self, key):
        try:
            self.__getitem__(key)
            return True
        except Exception:
            return False


    def idOf(self, path):
        """
        Find the file ID for the given filename, or for the given file
        path (using "/" as the separator) relative to this folder.
        """

        def findInFolder(requestedPath, searchFolder):
            """
            Attempt to find filename in the given folder.
            pathSoFar is the path up through this point, as a list.
            """
            pathPart = requestedPath[0]
            if len(requestedPath) == 1:
                # It's hopefully a file in this folder.
                if pathPart in searchFolder.files:
                    # Yay!
                    return searchFolder.firstID + searchFolder.files.index(pathPart)
                else:
                    # Not here.
                    return None

            # Hopefully we have the requested subfolder...
            for subfolderName, subfolder in searchFolder.folders:
                if subfolderName == pathPart:
                    # Yup.
                    return findInFolder(requestedPath[1:], subfolder)
            # Welp.
            return None

        pathList = path.split('/')
        while not pathList[-1]: pathList = pathList[:-1]
        while not pathList[0]: pathList = pathList[1:]
        return findInFolder(pathList, self)


    def subfolder(self, path):
        """
        Find the Folder instance for the given subfolder name, or for
        the given folder path (using "/" as the separator) relative to
        this folder.
        """

        def findInFolder(requestedPath, searchFolder):
            """
            Attempt to find filename in the given folder.
            pathSoFar is the path up through this point, as a list.
            """
            pathPart = requestedPath[0]
            for subfolderName, subfolder in searchFolder.folders:
                if subfolderName == pathPart:
                    if len(requestedPath) == 1:
                        # Found the actual folder that was requested!
                        return subfolder
                    else:
                        # Search another level down
                        return findInFolder(requestedPath[1:], subfolder)
            # Welp.
            return None

        pathList = path.split('/')
        while not pathList[-1]: pathList = pathList[:-1]
        while not pathList[0]: pathList = pathList[1:]
        return findInFolder(pathList, self)



    def _strListUncombined(self, indent=0, fileList=None):
        """
        Return a list of (line, preview) pairs, where line is a whole
        printout line except for the preview, and preview is the
        preview. This lets _strList pad the previews to all fall in the
        same column.
        """
        L = []
        indentStr = ' ' * (indent + 1)

        # Print filenames first, since those have file IDs less than
        # those of files contained in subfolders

        for i, fileName in enumerate(self.files):

            fid = self.firstID + i

            if fileList is None or fid >= len(fileList):
                preview = None
            else:
                preview = _common.shortBytesRepr(fileList[fid], 0x10)

            L.append(('{fid:04d}' + indentStr + fileName, preview))

        for folderName, folder in self.folders:
            L.append(('{folder.firstID:04d}' + indentStr + folderName + '/', None))
            L.extend(folder._strListUncombined(indent + 4, fileList))

        return L


    def _strList(self, indent=0, fileList=None):
        """
        Return a list of lines that could be useful for a printout of
        the folder. fileList can be used to add previews of files.

        Even though this is an internal function, other ndspy modules
        (narc, for one) call it directly, so be careful if you change
        it!
        """

        strings = []

        uncombined = self._strListUncombined(indent, fileList)

        if uncombined:
            previewColumn = max(len(entry[0]) for entry in uncombined) + 4
        else:
            previewColumn = 4

        for line, preview in uncombined:
            if preview is not None:
                line += ' ' * (previewColumn - len(line))
                line += preview
            strings.append(line)

        return strings


    def __str__(self):
        return '\n'.join(self._strList())


    def __repr__(self):
        return ('{type(self).__name__}({self.folders!r}'
                ', {self.files!r}'
                ', {self.firstID!r})')


def load(fnt):
    """
    Create a Folder from filename table data. This is the inverse of
    save().
    """
    def loadFolder(folderId):
        """
        Load the folder with ID `folderId` and return it as a Folder.
        """
        folderObj = Folder()

        # Get the entries table offset and file ID from the top of the
        # fnt file
        off = 8 * (folderId & 0xFFF)
        entriesTableOff, fileID = struct.unpack_from('<IH', fnt, off)
        folderObj.firstID = fileID

        off = entriesTableOff

        # Read file and folder entries from the entries table
        while True:
            control, = struct.unpack_from('B', fnt, off); off += 1
            if control == 0:
                break

            # That first byte is a control byte that includes the length
            # of the upcoming string and if this entry is a folder
            len_, isFolder = control & 0x7F, control & 0x80

            name = fnt[off : off+len_].decode('latin-1'); off += len_

            if isFolder:
                # There's an additional 2-byte value with the subfolder
                # ID. Get that and load the folder
                subFolderID, = struct.unpack_from('<H', fnt, off); off += 2
                folderObj.folders.append((name, loadFolder(subFolderID)))
            else:
                folderObj.files.append(name)

        return folderObj

    # Root folder is always 0xF000
    return loadFolder(0xF000)


def save(root):
    """
    Generate a bytes object representing this root folder as a filename
    table. This is the inverse of load().
    """

    # folderEntries is a dict of tuples:
    # {
    #     folderID: (initialFileID, parentFolderID, b'file entries data'),
    #     folderID: (initialFileID, parentFolderID, b'file entries data'),
    # }
    # This is an intermediate representation of the filenames data that
    # can be converted to the final binary representation much more
    # easily than the nested lists can.
    folderEntries = {}

    # nextFolderID allows us to assign folder IDs in sequential order.
    # The root folder always has ID 0xF000.
    nextFolderID = 0xF000

    def parseFolder(d, parentID):
        """
        Parse a Folder and add its entries to folderEntries.
        `parentID` is the ID of the folder containing this one.
        """

        # Grab the next folder ID
        folderID = nextFolderID
        nextFolderID += 1

        # Create an entries table and add filenames and folders to it
        entriesTable = bytearray()
        for file in d.files:
            # Each file entry is preceded by a 1-byte length value.
            # Top bit must be 0 or else it'll be interpreted as a
            # folder.
            if len(file) > 127:
                raise ValueError('Filename "{file}" is {len(file)}'
                    ' characters long (maximum is 127)!')
            entriesTable.append(len(file))
            entriesTable.extend(file.encode('latin-1'))

        for folderName, folder in d.folders:
            # First, parse the subfolder and get its ID, so we can save
            # that to the entries table.
            otherID = parseFolder(folder, folderID)

            # Folder name is preceded by a 1-byte length value, OR'ed
            # with 0x80 to mark it as a folder.
            if len(folderName) > 127:
                raise ValueError('Folder name "{folderName}" is'
                    ' {len(folderName)} characters long (maximum is'
                     ' 127)!')
            entriesTable.append(len(folderName) | 0x80)
            entriesTable.extend(folderName.encode('latin-1'))

            # And the ID of the subfolder goes after its name, as a
            # 2-byte value.
            entriesTable.extend(struct.pack('<H', otherID))

        # And the entries table needs to end with a null byte to mark
        # its end.
        entriesTable.extend(b'\0')

        folderEntries[folderID] = (d.firstID, parentID, entriesTable)
        return folderID

    # The root folder's parent's ID is the total number of folders.
    def countFoldersIn(folder):
        folderCount = 0
        for _, f in folder.folders:
            folderCount += countFoldersIn(f)
        return folderCount + 1
    rootParentId = countFoldersIn(root)

    # Ensure that the root folder has the proper folder ID.
    rootId = parseFolder(root, rootParentId)
    assert rootId == 0xF000, 'Root FNT folder has incorrect root folder ID: {hex(rootId)}'

    # Allocate space for the folders table at the beginning of the file
    fnt = bytearray(len(folderEntries) * 8)

    # We need to iterate over the folders in order of increasing ID.
    for currentFolderID in sorted(folderEntries.keys()):
        fileID, parentID, entriesTable = folderEntries[currentFolderID]

        # Add the folder entries to the folder table
        offsetInFolderTable = 8 * (currentFolderID & 0xFFF)
        struct.pack_into('<IHH', fnt, offsetInFolderTable,
            len(fnt), fileID, parentID)

        # And tack the folder's entries table onto the end of the file
        fnt.extend(entriesTable)

    return fnt

def err(owo):
    if (owo == 0):
        raise Exception("owo)")

ICON_BANNER_LEN = 0x840


class NintendoDSRom:
    """
    A Nintendo DS ROM file (.nds).
    """

    def __init__(self, data=None):

        if data is None:
            self._initAsNew()
        else:
            self._initFromData(data)


    def _initAsNew(self):
        """
        Initialize this ROM with default values.
        """

        self.name = b''
        self.idCode = b'####'
        self.developerCode = b'\0\0'
        self.unitCode = 0
        self.encryptionSeedSelect = 0
        self.deviceCapacity = 9
        self.pad015 = 0
        self.pad016 = 0
        self.pad017 = 0
        self.pad018 = 0
        self.pad019 = 0
        self.pad01A = 0
        self.pad01B = 0
        self.pad01C = 0
        self.region = 0
        self.version = 0
        self.autostart = 0
        self.arm7Len = 0
        self.arm9Len = 0
        self.arm7Offset = 0
        self.arm9Offset = 0
        self.arm9EntryAddress = 0x2000800
        self.arm9RamAddress = 0x2000000
        self.arm7EntryAddress = 0x2380000
        self.arm7RamAddress = 0x2380000
        self.normalCardControlRegisterSettings = 0x0416657
        self.secureCardControlRegisterSettings = 0x81808f8
        self.secureAreaChecksum = 0x0000
        self.secureTransferDelay = 0x0D7E
        self.arm9CodeSettingsPointerAddress = 0
        self.arm7CodeSettingsPointerAddress = 0
        self.secureAreaDisable = b'\0' * 8
        self.pad088 = b'\0' * 0x38
        self.nintendoLogo = (b'$\xff\xaeQi\x9a\xa2!=\x84\x82\n\x84\xe4\t\xad'
            b"\x11$\x8b\x98\xc0\x81\x7f!\xa3R\xbe\x19\x93\t\xce \x10FJJ\xf8'1"
            b'\xecX\xc7\xe83\x82\xe3\xce\xbf\x85\xf4\xdf\x94\xceK\t\xc1\x94V'
            b"\x8a\xc0\x13r\xa7\xfc\x9f\x84Ms\xa3\xca\x9aaX\x97\xa3'\xfc\3\x98"
            b'v#\x1d\xc7a\3\4\xaeV\xbf8\x84\0@\xa7\x0e\xfd\xffR\xfe\3o\x950'
            b'\xf1\x97\xfb\xc0\x85`\xd6\x80%\xa9c\xbe\3\1N8\xe2\xf9\xa24\xff'
            b'\xbb>\3Dx\0\x90\xcb\x88\x11:\x94e\xc0|c\x87\xf0<\xaf\xd6%\xe4'
            b'\x8b8\n\xacr!\xd4\xf8\7')
        self.debugRomAddress = 0
        self.pad16C = b'\0' * 0x94
        self.pad200 = b'\0' * 0x3E00

        self.rsaSignature = b''

        self.arm9 = b''
        self.arm9PostData = b''
        self.arm7 = b''
        self.arm9OverlayTable = b''
        self.arm7OverlayTable = b''
        self.iconBanner = b''
        self.debugRom = b''

        self.filenames = Folder()
        self.files = []
        self.sortedFileIds = []
        self.romSizeOrRsaSigOffset = 0

    
    def _initFromData(self, data):
        """
        Initialize this ROM from existing data.
        """
        # I could read the header as one huge struct,
        # but... no.
        self.headerOffset = 0
        data = bytearray(data)
        if len(data) < 0x200:
            data.extend(b'\0' * (0x200 - len(data)))
            assert len(data) == 0x200, 'ROM data extension to length 0x200 failed (actual new length' + hex(len(data)) + ')'

        def readRaw(length):
            retVal = data[self.headerOffset : self.headerOffset+length]
            self.headerOffset += length
            return retVal
        def read8():
            
            retVal = data[self.headerOffset]
            self.headerOffset += 1
            return retVal
        def read16():
            
            retVal, = struct.unpack_from('<H', data, self.headerOffset)
            self.headerOffset += 2
            return retVal
        def read32():
            
            retVal, = struct.unpack_from('<I', data, self.headerOffset)
            self.headerOffset += 4
            return retVal

        assert self.headerOffset == 0, '(Load) Header offset check at 0x00: '+ hex(self.headerOffset)
        self.name = readRaw(12).rstrip(b'\0')
        self.idCode = readRaw(4)
        self.developerCode = readRaw(2)
        self.unitCode = read8()
        self.encryptionSeedSelect = read8()
        self.deviceCapacity = read8()
        assert self.headerOffset == 0x15, '(Load) Header offset check at 0x15: ' + hex(self.headerOffset)
        self.pad015 = read8()
        self.pad016 = read8()
        self.pad017 = read8()
        self.pad018 = read8()
        self.pad019 = read8()
        self.pad01A = read8()
        self.pad01B = read8()
        self.pad01C = read8()
        self.region = read8()
        self.version = read8()
        self.autostart = read8()
        assert self.headerOffset == 0x20, '(Load) Header offset check at 0x20: ' + hex(self.headerOffset)
        self.arm9Offset = read32()
        self.arm9EntryAddress = read32()
        self.arm9RamAddress = read32()
        self.arm9Len = read32()
        self.arm7Offset = read32()
        self.arm7EntryAddress = read32()
        self.arm7RamAddress = read32()
        self.arm7Len = read32()
        assert self.headerOffset == 0x40, '(Load) Header offset check at 0x40: ' + hex(self.headerOffset)
        fntOffset = read32()
        fntLen = read32()
        fatOffset = read32()
        fatLen = read32()
        arm9OvTOffset = read32()
        arm9OvTLen = read32()
        arm7OvTOffset = read32()
        arm7OvTLen = read32()
        assert self.headerOffset == 0x60, '(Load) Header offset check at 0x60: ' + hex(self.headerOffset)
        self.normalCardControlRegisterSettings = read32()
        self.secureCardControlRegisterSettings = read32()
        iconBannerOffset = read32()
        self.secureAreaChecksum = read16() # TODO: Actually recalculate
                                           # this upon saving.
        self.secureTransferDelay = read16()
        assert self.headerOffset == 0x70, '(Load) Header offset check at 0x70: ' + hex(self.headerOffset)
        self.arm9CodeSettingsPointerAddress = read32()
        self.arm7CodeSettingsPointerAddress = read32()
        self.secureAreaDisable = readRaw(8)
        assert self.headerOffset == 0x80, '(Load) Header offset check at 0x80: ' + hex(self.headerOffset)
        self.romSizeOrRsaSigOffset = read32()
        headerSize = read32()
        self.pad088 = readRaw(0x38)
        self.nintendoLogo = readRaw(0x9C)
        nintendoLogoChecksum = read16()
        headerChecksum = read16()
        assert self.headerOffset == 0x160, '(Load) Header offset check at 0x160: ' + hex(self.headerOffset)
        debugRomOffset = read32()
        debugRomSize = read32()
        self.debugRomAddress = read32()
        self.pad16C = readRaw(0x94)
        assert self.headerOffset == 0x200, '(Load) Header offset check at 0x200: ' + hex(self.headerOffset)
        self.pad200 = data[0x200 : min(self.arm9Offset, len(data))]

        # Read the RSA signature file
        realSigOffset = 0
        if len(data) >= 0x1004:
            realSigOffset, = struct.unpack_from('<I', data, 0x1000)
        if not realSigOffset and len(data) > (self.romSizeOrRsaSigOffset):
            realSigOffset = (self.romSizeOrRsaSigOffset)
        self.rsaSignature = b''
        if realSigOffset:
            self.rsaSignature = data[realSigOffset : min(len(data), realSigOffset + 0x88)]

        # Read arm9, arm7, FNT, FAT, overlay tables, icon banner
        self.arm9 = data[self.arm9Offset : self.arm9Offset+self.arm9Len]
        self.arm7 = data[self.arm7Offset : self.arm7Offset+self.arm7Len]
        fnt = data[fntOffset : fntOffset+fntLen]
        fat = data[fatOffset : fatOffset+fatLen]
        self.arm9OverlayTable = data[
            arm9OvTOffset : arm9OvTOffset + arm9OvTLen]
        self.arm7OverlayTable = data[
            arm7OvTOffset : arm7OvTOffset + arm7OvTLen]
        if iconBannerOffset:
            self.iconBanner = \
                data[iconBannerOffset : iconBannerOffset + ICON_BANNER_LEN]
        else:
            self.iconBanner = b''
        if debugRomOffset:
            self.debugRom = \
                data[debugRomOffset : debugRomOffset + debugRomSize]
        else:
            self.debugRom = b''

        # Read the small amount of data immediately following arm9
        # No idea what this is, though...
        # Probably related to the "code settings" stuff in code.py.
        arm9PostData = bytearray()
        arm9PostDataOffset = self.arm9Offset+self.arm9Len
        while (data[arm9PostDataOffset:arm9PostDataOffset+4]
                == b'\x21\x06\xC0\xDE'):
            arm9PostData.extend(data[arm9PostDataOffset:arm9PostDataOffset+12])
            arm9PostDataOffset += 12
        self.arm9PostData = arm9PostData

        # Read the filename table
        if fnt:
            self.filenames = load(fnt)
        else:
            self.filenames = Folder()

        # Read files
        self.files = []
        self.sortedFileIds = []
        if fat:
            offset2Id = {}
            for i in range(len(fat) // 8):
                startOffset, endOffset = struct.unpack_from('<II', fat, 8 * i)
                self.files.append(data[startOffset:endOffset])
                offset2Id[startOffset] = i
            for off in sorted(offset2Id):
                self.sortedFileIds.append(offset2Id[off])


    @classmethod
    def fromFile(cls, filePath):
        """
        Load a ROM from a filesystem file.
        """
        with open(filePath, 'rb') as f:
            return cls(f.read())

    def loadArm9(self):
        """
        Create a MainCodeFile object representing the main ARM9 code
        file in this ROM.
        """
        return code.MainCodeFile(self.arm9,
                                 self.arm9RamAddress,
                                 self.arm9CodeSettingsPointerAddress)


    def loadArm7(self):
        """
        Create a MainCodeFile object representing the main ARM7 code
        file in this ROM.
        """
        return code.MainCodeFile(self.arm7,
                                 self.arm7RamAddress,
                                 self.arm7CodeSettingsPointerAddress)


    def loadArm9Overlays(self, idsToLoad=None):
        """
        Create a dictionary of this ROM's ARM9 overlays.
        """
        def callback(ovID, fileID):
            return self.files[fileID]
        return code.loadOverlayTable(self.arm9OverlayTable, callback, idsToLoad)


    def loadArm7Overlays(self, idsToLoad=None):
        """
        Create a dictionary of this ROM's ARM7 overlays.
        """
        def callback(ovID, fileID):
            return self.files[fileID]
        return code.loadOverlayTable(self.arm7OverlayTable, callback, idsToLoad)


    def getFileByName(self, filename):
        """
        Return the data for the file with the given filename (path).
        This is a convenience function.
        """
        fid = self.filenames.idOf(filename)
        if fid is None:
            raise ValueError('Cannot find file ID of "' + filename + '"')
        return self.files[fid]


    def setFileByName(self, filename, data):
        """
        Replace the data for the file with the given filename (path)
        with the given data. This is a convenience function.
        """
        fid = self.filenames.idOf(filename)
        if fid is None:
            raise ValueError('Cannot find file ID of "' + filename + '"')
        self.files[fid] = data


    def __str__(self):
        title = repr(bytes(self.name))[2:-1].rstrip(' ')
        code = repr(bytes(self.idCode))[2:-1]
        return '<rom "' + title + '" (' + code + ')>'


    def __repr__(self):

        return type(self).__name__


def MakeReg(name, offset, size, count=0):
    idc.MakeNameEx(offset, name, idc.SN_NOCHECK | idc.SN_NOWARN)
    if (size == 1):
	    idc.MakeByte(offset)
    elif size == 2:
        idc.MakeWord(offset)
    elif size == 4:
        idc.MakeDword(offset)
    else:
        raise NotImplementedError("Register size invalid! Name: " + name)
        
    if (count != 0):
        idc.make_array(offset, count)
            

"""
// general memory range defines
#define		PAL			((u16 *) 0x05000000)
#define		VRAM1		((u16 *) 0x06000000)
#define		VRAM2		((u16 *) 0x06200000)

//#define		OAM			((u16 *) 0x07000000)
#define		CART		((u16 *) 0x08000000)
"""

def MakeVideoRegs():

    MakeReg("REG_DisplayCnt", 0x04000000, 4)
    MakeReg("REG_DisplayStatus", 0x04000004, 2)
    MakeReg("REG_VCount", 0x04000006, 2)
    MakeReg("REG_BG0CNT", 0x4000008, 2)
    MakeReg("REG_BG1CNT", 0x400000a, 2)
    MakeReg("REG_BG2CNT", 0x400000c, 2)
    MakeReg("REG_BG3CNT", 0x400000e, 2)
    MakeReg("REG_BG0HOFS", 0x4000010, 2)
    MakeReg("REG_BG0VOFS", 0x4000012, 2)
    MakeReg("REG_BG1HOFS", 0x4000014, 2)
    MakeReg("REG_BG1VOFS", 0x4000016, 2)
    MakeReg("REG_BG2HOFS", 0x4000018, 2)
    MakeReg("REG_BG2VOFS", 0x400001a, 2)
    MakeReg("REG_BG3HOFS", 0x400001c, 2)
    MakeReg("REG_BG3VOFS", 0x400001e, 2)
    MakeReg("REG_BG2PA", 0x4000020, 2)
    MakeReg("REG_BG2PB", 0x4000022, 2)
    MakeReg("REG_BG2PC", 0x4000024, 2)
    MakeReg("REG_BG2PD", 0x4000026, 2)
    MakeReg("REG_BG2X", 0x4000028, 4)
    MakeReg("REG_BG2Y", 0x400002c, 4)
    MakeReg("REG_BG3PA", 0x4000030, 2)
    MakeReg("REG_BG3PB", 0x4000032, 2)
    MakeReg("REG_BG3PC", 0x4000034, 2)
    MakeReg("REG_BG3PD", 0x4000036, 2)
    MakeReg("REG_BG3X", 0x4000038, 4)
    MakeReg("REG_BG3Y", 0x400003c, 4)
    MakeReg("REG_WIN0H", 0x4000040, 2)
    MakeReg("REG_WIN1H", 0x4000042, 2)
    MakeReg("REG_WIN0V", 0x4000044, 2)
    MakeReg("REG_WIN1V", 0x4000046, 2)
    MakeReg("REG_WININ", 0x4000048, 2)
    MakeReg("REG_WINOUT", 0x400004a, 2)
    MakeReg("REG_MOSAIC", 0x400004c, 2)
    MakeReg("REG_BLDCNT", 0x4000050, 2)
    MakeReg("REG_BLDY", 0x4000054, 2)
    MakeReg("REG_VCOUNT2", 0x4001006, 2)
    MakeReg("REG_BG0CNT2", 0x4001008, 2)
    MakeReg("REG_BG1CNT2", 0x400100a, 2)
    MakeReg("REG_BG2CNT2", 0x400100c, 2)
    MakeReg("REG_BG3CNT2", 0x400100e, 2)
    MakeReg("REG_BG2PA2", 0x4001020, 2)
    MakeReg("REG_BG2PB2", 0x4001022, 2)
    MakeReg("REG_BG2PC2", 0x4001024, 2)
    MakeReg("REG_BG2PD2", 0x4001026, 2)
    MakeReg("REG_BG2X2", 0x4001028, 4)
    MakeReg("REG_BG2Y2", 0x400102c, 4)
    MakeReg("REG_BG3PA2", 0x4001030, 2)
    MakeReg("REG_BG3PB2", 0x4001032, 2)
    MakeReg("REG_BG3PC2", 0x4001034, 2)
    MakeReg("REG_BG3PD2", 0x4001036, 2)
    MakeReg("REG_BG3X2", 0x4001038, 4)
    MakeReg("REG_BG3Y2", 0x400103c, 4)
    MakeReg("REG_WIN0H2", 0x4001040, 2)
    MakeReg("REG_WIN1H2", 0x4001042, 2)
    MakeReg("REG_WIN0V2", 0x4001044, 2)
    MakeReg("REG_WIN1V2", 0x4001046, 2)
    MakeReg("REG_WININ2", 0x4001048, 2)
    MakeReg("REG_WINOUT2", 0x400104a, 2)
    MakeReg("REG_MOSAIC2", 0x400104c, 2)
    MakeReg("REG_BLDCNT2", 0x4001050, 2)
    MakeReg("REG_BLDY2", 0x4001054, 2)

def MakeVMemRegs():
    MakeReg("REG_VMEM_PAL_BG_FB1", 0x05000000, 2, 0x200)
    MakeReg("REG_VMEM_PAL_FG_FB1", 0x05000200, 2, 0x200)
    MakeReg("REG_VMEM_PAL_BG_FB2", 0x05000400, 2, 0x200)
    MakeReg("REG_VMEM_PAL_FG_FB2", 0x05000600, 2, 0x200)
    MakeReg("REG_VMEM_BankCnt", 0x04000240, 2)

def MakeJoypadRegs():
    MakeReg("REG_JP_KeyInput", 0x04000130, 2)
    MakeReg("REG_JP_KeyCnt", 0x04000132, 2)    

def MakeSystemRegs():
    MakeReg("REG_Sys_WaitCnt", 0x04000204, 2)
    MakeReg("REG_Sys_IME", 0x04000208, 2)
    MakeReg("REG_Sys_IE", 0x04000210, 4)
    MakeReg("REG_Sys_IF", 0x04000214, 4)
    MakeReg("REG_Sys_HaltCnt", 0x04000230, 2)

def MakeARM7Regs():
    MakeReg("REG_ARM7_PowerCnt", 0x04000304, 2)
    MakeReg("REG_ARM7_SPI_CR", 0x040001C0, 2)
    MakeReg("REG_ARM7_SPI_Data", 0x040001C2, 2)

def MakeARM9Regs():
    MakeReg("REG_ARM9_PowerCnt", 0x04000308, 2)

def accept_file(li, n):
    ndsRom = NintendoDSRom(li.read(li.size()))
    if ((ndsRom.name != b'')):
        return "Nintendo DS (" + str(ndsRom.name) + ")"
    return 0

def load_file(li, neflags, format):
    li.seek(0)
    ndsRom = NintendoDSRom(li.read(li.size()))
    retval = 1

    useArm9 = ask_yn(1, "This ROM potentially contains both ARM9 and ARM7 code\nDo you want to load the ARM9 binary?")
    if (useArm9 == -1):
        useArm9 = 0
    
    useArm9 = bool(useArm9)

    proc = ""
    startEA = 0
    endEA = 0
    offset = 0
    entryAddr = 0
    size = 0
    name = ""
    rom = ""
    if (useArm9):
        name = "ARM9 ROM"
        proc = "ARM"
        entryAddr = ndsRom.arm9EntryAddress
        startEA = ndsRom.arm9RamAddress
        endEA = ndsRom.arm9RamAddress + ndsRom.arm9Len
        offset = ndsRom.arm9Offset
        size = ndsRom.arm9Len
        rom = ndsRom.arm9
    else:
        name = "ARM7 ROM"
        proc = "ARM710A"
        entryAddr = ndsRom.arm7EntryAddress
        startEA = ndsRom.arm7RamAddress
        endEA = ndsRom.arm7RamAddress + ndsRom.arm7Len
        offset = ndsRom.arm7Offset
        size = ndsRom.arm7Len
        rom = ndsRom.arm7

    idaapi.set_processor_type(proc, idaapi.SETPROC_LOADER_NON_FATAL|idaapi.SETPROC_LOADER)
    
    memory =  \
    [
        [ startEA, endEA, "RAM" ],
        [ 0x04000000, 0x04001056, "General_Regs" ],
        [ 0x05000000, 0x05000600, "VMEM_Regs" ],
    ]

    if ((startEA < memory[0][0] or endEA > memory[0][1]) and (startEA < memory[1][0] or endEA > memory[1][1]) and (startEA < memory[2][0] or endEA > memory[2][1])):
        raise Exception("ROM not mapped into valid mem!")

    for segment in memory:
        idc.AddSeg(segment[0], segment[1], 0, 1, idaapi.saRelPara, idaapi.scPub)
        idc.RenameSeg(segment[0], segment[2])

        if "RAM" not in segment[2]:
            for i in xrange(segment[0], segment[1]):
		        idc.PatchByte(i, 0)
    
    idaapi.add_entry(entryAddr, entryAddr, "start", 1)
    idc.MakeNameEx(entryAddr, "start", idc.SN_NOCHECK | idc.SN_NOWARN)
    idaapi.cvar.inf.startIP = entryAddr
    idaapi.cvar.inf.beginEA = entryAddr
    ida_segment.set_selector(1, 0)
    idaapi.cvar.inf.startCS = 1
    

    li.seek(0)
    li.file2base(offset, startEA, endEA, 1)

    idaapi.cvar.inf.startCS = 0
    idaapi.cvar.inf.startIP = entryAddr
    
    idc.ExtLinA(startEA, 1,  "; Title : " + str(ndsRom.name))
    idc.ExtLinA(startEA, 1,  "; Software Version: " + str(ndsRom.version))

    # Add TwlHdr
    MakeVideoRegs()
    MakeVMemRegs()
    MakeJoypadRegs()
    MakeSystemRegs()
    if name == "ARM7 ROM":
        MakeARM7Regs()
    else:
        MakeARM9Regs()


    print("Done! Entry point @ " + hex(entryAddr))
    return 1
