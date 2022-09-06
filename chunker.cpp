#include "chunker.h"

Chunker::Chunker() { }

Chunker::~Chunker() { }

quint16 Chunker::GetChecksum(QByteArray *Block) { return qChecksum(QByteArrayView(*Block), Qt::ChecksumIso3309); }

QByteArrayList Chunker::ArmorData(QByteArray *Data, qsizetype *ChunkSize) {
    QByteArrayList Result;
    QUuid UUID = QUuid::createUuid();
    qsizetype RealChunkSize = (*ChunkSize) - sizeof(UUID.toRfc4122()) - sizeof(quint32) - sizeof(quint32) - sizeof(quint16);
    const quint32 ChunkCount = ((*Data).length() / RealChunkSize) + 1;
    for (auto Pos = 0; Pos < ChunkCount; Pos++) {
        QByteArray Block;
        QDataStream Stream(&Block, QIODeviceBase::WriteOnly);
        Stream << UUID.toRfc4122() << (Pos + 1) << ChunkCount << (*Data).mid(Pos * RealChunkSize, RealChunkSize);
        Stream << Chunker::GetChecksum(&Block);
        Result.push_back(Block);
    }
    return Result;
}

Chunker::MessageBlock Chunker::DearmorChunk(QByteArray *Block) {
    Chunker::MessageBlock Result;
    QDataStream Stream(Block, QIODeviceBase::ReadOnly);
    QByteArray ClearBlock = (*Block).chopped(sizeof(quint16));
    QByteArray BytesUUID;
    quint16 Checksum;
    Stream >> BytesUUID >> Result.Number >> Result.Total >> Result.Data >> Checksum;
    Result.UUID = QUuid::fromRfc4122(QByteArrayView(BytesUUID));
    if (Chunker::GetChecksum(&ClearBlock) != Checksum) throw std::runtime_error("Checksums are not equal");
    return Result;
}

bool Chunker::CheckIntegrity(QUuid *UUID, QByteArray *Reconstructed) {
    quint32 Size = this->Sizes[*UUID];
    if (this->Stack[*UUID]->size() > Size) throw std::runtime_error("Corrupted message blocks");
    if (this->Stack[*UUID]->size() < Size) return false;
    for (quint32 Counter = 0; Counter < Size; Counter++) {
        if (!(this->Stack[*UUID]->contains(Counter + 1))) return false;
        (*Reconstructed).append((*(this->Stack[*UUID]))[Counter + 1].Data);
    }
    return true;
}

CHUNKER Chunker::AddBlock(QByteArray *Block, ChunkedMessage *Message) {
    Chunker::MessageBlock DecodedBlock = Chunker::DearmorChunk(Block);
    if (!this->Sizes.contains(DecodedBlock.UUID)) {
        this->Sizes[(QUuid)DecodedBlock.UUID] = (quint32)DecodedBlock.Total;
        this->Stack[(QUuid)DecodedBlock.UUID] = new QMap<quint32, Chunker::MessageBlock>;
    }
    (*(this->Stack[DecodedBlock.UUID]))[(quint32)(DecodedBlock.Number)] = Chunker::MessageBlock(DecodedBlock);
    QByteArray ReconstructedData;
    if (this->CheckIntegrity(&DecodedBlock.UUID, &ReconstructedData)) {
        (*Message).UUID = (QUuid)DecodedBlock.UUID;
        (*Message).Data = (QByteArray)ReconstructedData;
        this->Sizes.remove(DecodedBlock.UUID);
        delete this->Stack[DecodedBlock.UUID];
        this->Stack.remove(DecodedBlock.UUID);
        return CHUNKER::MESSAGE_READY;
    }
    return CHUNKER::BLOCK_ADDED;
}
