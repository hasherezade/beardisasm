#include "main.h"

#include <iostream>
#include <bearparser/bearparser.h>
#include <beardisasm.h>

#include <iostream>
#include <fstream>

#define MINBUF 0x200

using namespace minidis;

QString g_fileName;

//Utils:

FileView* tryLoading(QString &fName)
{
    FileView *fileView = NULL;
    bufsize_t maxMapSize = FILE_MAXSIZE;
    do {
        if (!QFile::exists(fName)) {
            std::cerr << "[ERROR] " << "The file does not exist" << std::endl;
            break;
        }
        try {
            fileView = new FileView(fName, maxMapSize);
        } catch (BufferException &e1) {
            std::cerr << "[ERROR] " << e1.what() << std::endl;
            if (maxMapSize == 0) break;
        }
    } while (!fileView);
    
    return fileView;
}

offset_t convertHex(const QString &str)
{
    offset_t offset = INVALID_ADDR;
    bool bStatus = false;
    offset = str.toUInt(&bStatus,16);
    if (!bStatus) {
        return INVALID_ADDR;
    }
    return offset;
}

QString getFileName(QString fullPath)
{
    int lastSlashIndex = fullPath.lastIndexOf(QChar('/'));
    if (lastSlashIndex == -1) {
        lastSlashIndex = fullPath.lastIndexOf(QChar('\\'));  // For Windows paths
    }
    return fullPath.mid(lastSlashIndex + 1);
}

int get_func_type(size_t count)
{
    if (count == 172 || count == 173)
        return 1;
    if (count == 98 || count == 99)
        return 2;
    if (count == 56 || count == 57)
        return 3;
    return 0;
}
//Disasm:

offset_t funcNameToOffset(Executable *exe, const QString funcName, const Executable::addr_type aType = Executable::RAW)
{
    QMap<offset_t, QString> entrypoints;
    if (!exe->getAllEntryPoints(entrypoints, aType)) {
        return INVALID_ADDR;
    }
    for (auto itr = entrypoints.begin(); itr != entrypoints.end(); ++itr) {
        if (itr.value() == funcName) {
            return itr.key();
        }
    }
    return INVALID_ADDR;
}

void _disasmPeFile(PEFile *exe, offset_t func_offset, std::ofstream &outFile)
{
    if (!exe) return;

    const minidis::DisasmSettings basicSettings(0, false, true);
    
    minidis::PeDisasm disasm1(exe);
    disasm1.init(func_offset);
    
    QMap<offset_t, QString> entrypoints;
    exe->getAllEntryPoints(entrypoints, Executable::VA);

    std::vector<QString> vec;
    size_t i = 0;
    if (!disasm1.fillTable(basicSettings)) return;
    for (i = 0; ; i++) {
        DisasmChunk* chunk = disasm1.getChunkAtIndex(i);
        if (!chunk) break;
        
        const QString disasmLine = chunk->toString();
        if (!disasmLine.contains("movabs")) continue;
        
        //std::cout << std::hex << disasm1.getOffset(i, Executable::VA)
        //    << " : "
        QStringList parts = disasmLine.split(',');
        QString hexValue = parts.last().trimmed();
        vec.push_back(hexValue);
        
    }
    outFile << get_func_type(i) << ",";
    outFile << "[ ";
    for (auto itr = vec.begin(); itr != vec.end(); ++itr) {
        outFile << itr->toStdString() << " ";
    }
    outFile << "]";
}

void disasmPeFile(PEFile *exe, offset_t func_offset, std::ofstream &outFile)
{
    if (func_offset != INVALID_ADDR) {
        _disasmPeFile(exe, func_offset, outFile);
        return;
    }

    QMap<offset_t, QString> entrypoints;
    exe->getAllEntryPoints(entrypoints, Executable::RAW);
    
    for (auto itr = entrypoints.begin(); itr != entrypoints.end(); ++itr) {
        const QString funcName = itr.value();
        if (!funcName.contains("_Z21f")) continue;
        
        const offset_t offset = itr.key();
        outFile << g_fileName.toStdString() 
            << "," << funcName.toStdString() << ",";
        _disasmPeFile(exe, offset, outFile);
        outFile << "\n";
    }
    return;
}

int parseFile(QString filePath, offset_t func_raw_addr, std::ofstream &outFile)
{
    int status = 0;
    g_fileName = getFileName(filePath);
    offset_t offset = INVALID_ADDR;

    try {
        FileView* fileView = tryLoading(filePath);
        if (!fileView) return -1;

        ExeFactory::exe_type exeType = ExeFactory::findMatching(fileView);
        if (exeType == ExeFactory::NONE) {
           std::cerr << "Type not supported\n";
           ExeFactory::destroy();
           return (-1);
        }
#ifdef _DEBUG
        std::cout << "Type: " << ExeFactory::getTypeName(exeType).toStdString() << std::endl;
#endif //_DEBUG
        bufsize_t readableSize = fileView->getContentSize();
        bufsize_t allocSize = (readableSize < MINBUF) ? MINBUF : readableSize;

        //std::cout << "Buffering..." << std::endl;
        ByteBuffer *buf = new ByteBuffer(fileView, 0, allocSize);
        delete fileView;

        //std::cout << "Parsing executable..." << std::endl;
        Executable *exe = ExeFactory::build(buf, exeType);
        PEFile *pe = dynamic_cast<PEFile*>(exe);
        if (pe) {
            disasmPeFile(pe, func_raw_addr, outFile);
        }
        
        delete exe;
        delete buf;
        
    } catch (CustomException &e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
        status = -1;
    }
    ExeFactory::destroy();
    return status;
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    ExeFactory::init();

    if (argc < 4) {
        std::cout << "Bearparser version: " <<  BEARPARSER_VERSION << "\n";
        std::cout << "Args: <dir_path> <start> <stop>\n";
        return 0;
    }
    
    bool bStatus = false;
    size_t start = QString(argv[2]).toUInt(&bStatus,10);
    if (!bStatus) {
        std::cout << "Start is not a valid number!\n";
        return 0;
    }
    size_t stop = QString(argv[3]).toUInt(&bStatus,10);
    if (!bStatus) {
        std::cout << "Stop is not a valid number!\n";
        return 0;
    }
    if (stop < start) {
        std::cerr << "Invalid stop: " << std::dec << stop << " < " << start << std::endl;
        return (-1);
    }
    std::string outFilename = std::string("dlls_list_") + argv[2] + "_" + argv[3] + ".csv";
    std::ofstream outFile(outFilename);   // open output file
    if (!outFile.is_open()) {
        std::cerr << "Could not open file for writing!" << std::endl;
        return (-1);
    }

    QString dirPath = QString(argv[1]);
    for (size_t i = start; i < stop; i++) {
        QString fileName = QString("%1.dll").arg(i, 4, 10, QChar('0'));
        QString filePath = dirPath + "//" + fileName;
        parseFile(filePath, INVALID_ADDR, outFile);
    }
    
    outFile.close();   // always close the file
    return 0;
}
