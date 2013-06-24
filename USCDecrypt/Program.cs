using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using BlueBlocksLib.FileAccess;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace USCDecrypt
{
    class Program
    {
        const int JIS = 932;

        class DataDat
        {
            public int header;
            public int metadataSize;
            public int mystery2;
            public int startpoint;
            public int fileRecordStartPoint;
            public int dirRecordStartPoint;
            public int mystery6;

            public int DirRecordPosition()
            {
                FileRecord.nameOffsetStart = startpoint;
                FileRecord.fileRecordOffsetStart = startpoint + fileRecordStartPoint;
                FileRecord.dirRecordOffsetStart = startpoint + dirRecordStartPoint;

                return startpoint + dirRecordStartPoint;
            }

            [Offset("DirRecordPosition()")]
            public DirInformation root;

            public int AfterFileList()
            {
                return startpoint + fileRecordStartPoint;
            }


            [Offset("AfterFileList()")]
            public FileRecordTable frtable;

        }

        [DebuggerDisplay("Name = {name.Name} Mystery = {name.mystery} Mystery9 = {rec.mystery9} Mystery10 = {rec.mystery10} Pos = {rec.location} Length = {rec.filesize} Type = {rec.filetype}")]
        class FileInfo
        {
            public FileRecord rec;
            public FileName name;
        }

        [StructLayout(LayoutKind.Sequential)]
        class FileNameList
        {
            public int empty;

            [ArraySize(213)]
            public FileName[] table;

            [PopulateWithCurrentOffset]
            public long end;
        }

        [Alignment(4)]
        [DebuggerDisplay("Name = {Name} Offset = {offset}")]
        [StructLayout(LayoutKind.Sequential)]
        class FileName
        {

            [PopulateWithCurrentOffset]
            public long offset;

            public short type;
            public short mystery;

            [ArraySize(ArrayProperty.DefaultTerminated)]
            public byte[] name;

            [Alignment(4)]
            [ArraySize(ArrayProperty.DefaultTerminated)]
            public byte[] name2;

            public string BigName
            {
                get
                {
                    return Encoding.GetEncoding(JIS).GetString(name).Trim('\0');
                }
            }

            public string Name
            {
                get
                {
                    return Encoding.GetEncoding(JIS).GetString(name2).Trim('\0');
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        class FileRecordTable
        {
            [ArraySize(214)]
            public FileRecord[] table;
        }

        [Flags]
        enum FileType : uint
        {
            Directory = 0x10,
            File = 0x20,
            Mystery1 = 0x100,
            Unknown = 0xffffffff,
        }

        [DebuggerDisplay("pos = {pos} mystery = {mystery} numFiles = {numFiles} offset = {offset}")]
        [StructLayout(LayoutKind.Sequential)]
        class DirInformation
        {
            public int pos;
            public int mystery;
            public int numFiles;
            public int offset;

            //[Offset("recordPos()")]
            //public FileRecord theRecord;

            [Offset("filePos()")]
            [ArraySize("numFiles")]
            public FileRecord[] files;

            public int recordPos()
            {
                return FileRecord.fileRecordOffsetStart + pos;
            }

            public int filePos()
            {
                return FileRecord.fileRecordOffsetStart + offset;
            }
                 
        }

        [DebuggerDisplay("Name={Name} {name.type} Length={filesize} Position={location} Type={filetype} ")]
        [StructLayout(LayoutKind.Sequential)]
        class FileRecord
        {

            internal static int nameOffsetStart;
            internal static int fileRecordOffsetStart;
            internal static int dirRecordOffsetStart;

            [PopulateWithCurrentOffset]
            public long offset;

            public int nameOffset;
            public FileType filetype;
            public int mystery3;
            public int mystery4;
            public int mystery5;
            public int mystery6;
            public int mystery7;
            public int mystery8;
            public int location;
            public int filesize;
            public int mystery9;

            [ArraySize("IsDirectory()")]
            [Offset("DirectoryInformationPosition()")]
            public DirInformation[] dirinfo;

            [Offset("NameOffsetPosition()")]
            public FileName name;

            public int NameOffsetPosition()
            {
                return nameOffset + nameOffsetStart;
            }

            public int DirectoryInformationPosition()
            {
                return location + dirRecordOffsetStart;
            }

            public int IsDirectory()
            {
                if ((int)(filetype & FileType.Directory) != 0)
                {
                    return 1;
                }
                return 0;
            }

            public string Name
            {
                get
                {
                    if (nameOffset == 0)
                    {
                        return "DATA";
                    }
                    return name.Name;
                }
            }
        }

        class firstpart
        {
            [ArraySize(647)]
            public byte[] bytes;

            public string Contents
            {
                get
                {
                    return Encoding.GetEncoding(JIS).GetString(bytes).Trim('\0');
                }
            }
        }

        static void UnpackDir(BinaryReader br, DirInformation record, string path)
        {
            if (!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
            }

            foreach (var file in record.files)
            {
                Console.WriteLine("Unpacking file {0}", file.Name);
                if (file.IsDirectory() == 1)
                {
                    UnpackDir(br, file.dirinfo[0], Path.Combine(path, file.Name));
                }
                else
                {
                    br.BaseStream.Position = file.location + 28;
                    byte[] bytes = br.ReadBytes(file.filesize);
                    File.WriteAllBytes(Path.Combine(path, file.Name), bytes);
                }
            }
        }

        static void Main(string[] args)
        {
            string result = args[0] + ".dec";
            Decrypt(args[0], result);
            using (FormattedReader fr = new FormattedReader(result))
            {
                var data = fr.Read<DataDat>();

                UnpackDir(fr.BaseStream, data.root, Path.Combine(Path.GetDirectoryName(Path.GetFullPath(result)), "unpacked"));
            }
        }

        // for decrypting unlimited sunflower creation
        static void Decrypt(string file, string result)
        {
            Console.WriteLine("Decrypting file {0}", file);

            byte[] table = new byte[] {
                0x55, 0xaa, 0x20, 0x55,
                0x55, 0x06, 0x55, 0xaa,
                0x55, 0xd5, 0x7c, 0x66,
            };


            byte[] br = File.ReadAllBytes(file);
            byte[] bw = new byte[br.Length];
            int tableCursor = 0;
            for (int i = 0; i < br.Length; i++)
            {
                bw[i] = (byte)((br[i] ^ table[tableCursor]));
                tableCursor = (tableCursor + 1) % table.Length;
            }

            File.WriteAllBytes(result, bw);
        }
    }
}
