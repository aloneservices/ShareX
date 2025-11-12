using ProtoBuf;

namespace ShareX.UploadersLib.Proto;

[ProtoContract]
public class FileChunk
{
    [ProtoMember(1)] public uint Order { get; set; }
    [ProtoMember(2)] public byte[] Data { get; set; }
    [ProtoMember(3)] public byte[] Checksum { get; set; }
}