#ifndef CHUNKER_H
#define CHUNKER_H

#include <QByteArrayView>
#include <QDataStream>
#include <QException>
#include <QMap>
#include <QUuid>

enum CHUNKER {
    MESSAGE_READY = 0,
    BLOCK_ADDED
};

struct ChunkedMessage {
    QUuid UUID;
    QByteArray Data;
};

class Chunker {
public:
    Chunker();
    ~Chunker();
    static quint16 GetChecksum(QByteArray *Block);
    static QByteArrayList ArmorData(QByteArray *Data, qsizetype *ChunkSize);
    CHUNKER AddBlock(QByteArray *Block, ChunkedMessage *Message);
private:
    struct MessageBlock {
        QUuid UUID;
        quint32 Number;
        quint32 Total;
        QByteArray *Data;
    };
    QMap<QUuid, quint32> Sizes;
    QMap<QUuid, QMap<quint32, Chunker::MessageBlock*>*> Stack;
    MessageBlock DearmorChunk(QByteArray *Block);
    bool CheckIntegrity(QUuid *UUID, QByteArray *Reconstructed);
};

#endif // CHUNKER_H
