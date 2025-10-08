#include "main.h"

#include <iostream>
#include <bearparser/bearparser.h>
#include <beardisasm.h>

#define MINBUF 0x200

using namespace minidis;

QString g_fileName;

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

void disasmPeFile(PEFile *exe, offset_t func_offset)
{
    if (!exe) return;

    const minidis::DisasmSettings basicSettings(0, false, true);
    
    minidis::PeDisasm disasm1(exe);
    disasm1.init(func_offset);
    
    QMap<offset_t, QString> entrypoints;
    exe->getAllEntryPoints(entrypoints, Executable::VA);

    if (!disasm1.fillTable(basicSettings)) return;
    for (size_t i = 0; ; i++) {
        DisasmChunk* chunk = disasm1.getChunkAtIndex(i);
        if (!chunk) break;
        std::cout << std::hex << disasm1.getOffset(i, Executable::VA)
            << " : "
            << chunk->toString().toStdString();
            
        offset_t target = chunk->getTargetAddr();
        QString str = disasm1.getStringAt(target, chunk->getTargetAddrType());
        if (str.length() > 0) {
            std::cout << " : " << str.toStdString();
        }
        if (chunk->isBranching()) {
            offset_t targetVA = exe->convertAddr(target, chunk->getTargetAddrType(), Executable::VA);
            if (targetVA != INVALID_ADDR) {
                std::cout << " -> "
                    << std::hex << targetVA;
                auto fItr = entrypoints.find(targetVA);
                if (fItr != entrypoints.end()) {
                    std::cout << " ; " << g_fileName.toStdString() << "." << fItr->toStdString();
                }
            }
        }
        if (disasm1.isImportCall(i)) {
            std::cout << " ; " << disasm1.getImportName(target, chunk->getTargetAddrType()).toStdString();
        }
        std::cout << "\n";
    }
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

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    ExeFactory::init();

    if (argc < 2) {
        std::cout << "Bearparser version: " <<  BEARPARSER_VERSION << "\n";
        std::cout << "Args: <PE file> <func_name>\n";
        return 0;
    }

    int status = 0;
    QString filePath = QString(argv[1]);
    g_fileName = getFileName(filePath);
    offset_t offset = INVALID_ADDR;

    try {
        FileView* fileView = tryLoading(filePath);
        if (!fileView) return -1;

        ExeFactory::exe_type exeType = ExeFactory::findMatching(fileView);
        if (exeType == ExeFactory::NONE) {
           std::cerr << "Type not supported\n";
           ExeFactory::destroy();
           return 1;
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

        const offset_t ep_raw = exe->getEntryPoint(Executable::RAW);
        offset_t func_raw_addr = ep_raw;
        if (argc >= 2) {
            QString funcName = QString(argv[2]);
            offset_t addr = funcNameToOffset(exe, funcName);
            if (addr != INVALID_ADDR) {
                func_raw_addr = addr;
                std::cout << "[" << g_fileName.toStdString() << "." << funcName.toStdString() << "]" << std::endl;
            }
        }
        
        PEFile *pe = dynamic_cast<PEFile*>(exe);
        if (pe) {
            disasmPeFile(pe, func_raw_addr);
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
