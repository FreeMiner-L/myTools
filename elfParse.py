import copy
import struct


class PhTable:
    headMemberTuple = ('p_type', 'p_offset', 'p_vaddr', 'p_paddr', 'p_fileseze', 'p_memsz', 'p_flags', 'p_align')
    parseStr = '8L'

    def __init__(self):
        self.headDict = {}
        self.binData = []


class ShTable:
    headMemberTuple = ('sh_name', 'sh_type', 'sh_flags', 'sh_addr', 'sh_offset', 'sh_size', 'sh_link', 'sh_info',
                       'sh_addralign', 'sh_entsize')
    parseStr = '10L'

    def __init__(self):
        self.headDict = {}
        self.binData = []


class ElfInfo:
    headMemberTuple = ('e_ident', 'e_type', 'e_machine', 'e_version', 'e_entry', 'e_phoff', 'e_shoff', 'e_flags',
                       'e_ehsize', 'e_phentsize', 'e_phnum', 'e_shentsize', 'e_shnum', 'e_shstrndx')
    parseStr = '16p2H5L6H'

    def __init__(self, elfFile):
        self.elfFile = elfFile
        self.headDict = {}
        self.phTableList = []
        self.shTableList = []
        self.fp = open(elfFile, 'rb')
        pass

    def __unpack__(self, tableObject, headBytes):
        MemberTuple = struct.unpack(tableObject.parseStr, headBytes)
        for index, value in enumerate(MemberTuple):
            tableObject.headDict[tableObject.headMemberTuple[index]] = value
        return

    def __parseTableInfo__(self, offset, size, num, tableList, tableObject):
        for i in range(num):
            self.fp.seek(offset + i * size, 0)
            phHead = self.fp.read(size)
            table = tableObject()
            self.__unpack__(table, phHead)
            tableList.append(table)
        return

    def __createBin__(self):
        baseaddr = 0
        with open('application123.bin', 'wb') as fd:
            for i in self.phTableList:
                self.fp.seek(i.headDict['p_offset'])
                binData = self.fp.read(i.headDict['p_fileseze'])
                targetaddr = baseaddr
                fd.seek(targetaddr)
                fd.write(binData)
                pass
        return

    def __createStrTable__(self):

        pass

    def parse(self):
        elfHead = self.fp.read(52)
        self.__unpack__(self, elfHead)
        self.__parseTableInfo__(self.headDict['e_phoff'], self.headDict['e_phentsize'],
                                self.headDict['e_phnum'], self.phTableList, PhTable)
        # self.__createBin__()
        self.__parseTableInfo__(self.headDict['e_shoff'], self.headDict['e_shentsize'],
                                self.headDict['e_shnum'], self.shTableList, ShTable)
        pass


if __name__ == '__main__':
    elfParse = ElfInfo(
        r'C:\Users\Administrator\Documents\IAR Embedded Workbench\arm\9.10.2\ST\STM32F4xx\STM32Cube_FW_F4\Projects\STM32F446ZE-Nucleo\Examples\UART\UART_Printf\EWARM\STM32F446ZE_NUCLEO_144\Exe\Project.out')
    elfParse.parse()
