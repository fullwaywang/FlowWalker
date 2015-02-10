#include "pin.H"
#include <string>
#include <vector>
#define BLOCK_SZ 0x20000000
#define TAILBLANK_SZ 0x15

namespace WINDOWS
{
	//包含头文件，这里面定义的UINT等基本类型和Pin下的同名类型冲突，所以需要这样
#include <Windows.h>

	//以下是分析系统调用时需要用到的数据结构
	typedef struct _UNICODE_STRING
	{
		USHORT  Length;
		USHORT  MaximumLength;
		PWSTR   Buffer;
	} UNICODE_STRING, *PUNICODE_STRING;

	typedef struct _IO_STATUS_BLOCK
	{
		union
		{
			NTSTATUS Status;
			PVOID Pointer;
		};
		ULONG_PTR Information;
	} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

	typedef struct _OBJECT_ATTRIBUTES
	{
		ULONG  Length;
		HANDLE  RootDirectory;
		PUNICODE_STRING  ObjectName;
		ULONG  Attributes;
		PVOID  SecurityDescriptor;
		PVOID  SecurityQualityOfService;
	} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

	//typedef union _LARGE_INTEGER {
	//	struct {
	//		DWORD LowPart;
	//		LONG  HighPart;
	//	};
	//	struct {
	//		DWORD LowPart;
	//		LONG  HighPart;
	//	} u;
	//	LONGLONG QuadPart;
	//} LARGE_INTEGER, *PLARGE_INTEGER;

	typedef struct _FILE_POSITION_INFORMATION {
		LARGE_INTEGER CurrentByteOffset;
	} FILE_POSITION_INFORMATION, *PFILE_POSITION_INFORMATION;

	typedef enum _FILE_INFORMATION_CLASS { 
		FileDirectoryInformation                  = 1,
		FileFullDirectoryInformation,
		FileBothDirectoryInformation,
		FileBasicInformation,
		FileStandardInformation,
		FileInternalInformation,
		FileEaInformation,
		FileAccessInformation,
		FileNameInformation,
		FileRenameInformation,
		FileLinkInformation,
		FileNamesInformation,
		FileDispositionInformation,
		FilePositionInformation,
		FileFullEaInformation,
		FileModeInformation,
		FileAlignmentInformation,
		FileAllInformation,
		FileAllocationInformation,
		FileEndOfFileInformation,
		FileAlternateNameInformation,
		FileStreamInformation,
		FilePipeInformation,
		FilePipeLocalInformation,
		FilePipeRemoteInformation,
		FileMailslotQueryInformation,
		FileMailslotSetInformation,
		FileCompressionInformation,
		FileObjectIdInformation,
		FileCompletionInformation,
		FileMoveClusterInformation,
		FileQuotaInformation,
		FileReparsePointInformation,
		FileNetworkOpenInformation,
		FileAttributeTagInformation,
		FileTrackingInformation,
		FileIdBothDirectoryInformation,
		FileIdFullDirectoryInformation,
		FileValidDataLengthInformation,
		FileShortNameInformation,
		FileIoCompletionNotificationInformation,
		FileIoStatusBlockRangeInformation,
		FileIoPriorityHintInformation,
		FileSfioReserveInformation,
		FileSfioVolumeInformation,
		FileHardLinkInformation,
		FileProcessIdsUsingFileInformation,
		FileNormalizedNameInformation,
		FileNetworkPhysicalNameInformation,
		FileIdGlobalTxDirectoryInformation,
		FileIsRemoteDeviceInformation,
		FileAttributeCacheInformation,
		FileNumaNodeInformation,
		FileStandardLinkInformation,
		FileRemoteProtocolInformation,
		FileMaximumInformation 
	} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;
};

//extern ofstream fOutput2;
extern WINDOWS::LPBYTE proc;
extern WINDOWS::HANDLE hFileMapping;
extern WINDOWS::DWORD offset;
extern unsigned __int64 offset_p;
LEVEL_BASE::BOOL bActive = FALSE;
extern PIN_LOCK lock;
extern THREADID CurTid;
//extern string lastBBL;

//监视文件打开相关系统调用的变量
UINT num_create = 0, num_open = 0, num_read = 0, num_close = 0, num_move = 0;
UINT num_createsection = 0, num_mapviewofsection = 0, num_unmapviewofsection = 0;
wstring wstrTraceFileName;
LEVEL_BASE::BOOL MonitorExit = FALSE;


class FileStatus
{
public:
	UINT32 pFileHandle;
	UINT32 FileHandle;
	UINT32 pFileMappingHandle;
	UINT32 FileMappingHandle;
	LEVEL_BASE::BOOL JustAfterCreate;
	LEVEL_BASE::BOOL JustAfterRead;
	LEVEL_BASE::BOOL JustAfterCreateSection;
	LEVEL_BASE::BOOL JustAfterMapViewOfSection;
	WINDOWS::PIO_STATUS_BLOCK pio_status;
	ADDRINT InitTaintBuffer,InitTaintBufferMapping, pInitTaintBufferMapping;
	WINDOWS::LARGE_INTEGER FileOffset, FileMappingOffset;
	WINDOWS::PLARGE_INTEGER pFileMappingOffset;
	WINDOWS::SIZE_T FileMappingSize;
	WINDOWS::PSIZE_T pFileMappingSize;

	FileStatus():pFileHandle(NULL),FileHandle(NULL),pFileMappingHandle(NULL),FileMappingHandle(NULL),
		JustAfterCreate(FALSE),JustAfterRead(FALSE),JustAfterCreateSection(FALSE),JustAfterMapViewOfSection(FALSE)
	{
		FileOffset.QuadPart = 0;
	}
};
vector<FileStatus*> FileStatusList;

inline VOID String2WString ( const string szStr, wstring& wszStr )
{
	int nLength = WINDOWS::MultiByteToWideChar ( CP_ACP, 0, szStr.c_str(), -1, NULL, NULL );
	WINDOWS::LPWSTR lpwszStr = new wchar_t[nLength];
	WINDOWS::MultiByteToWideChar ( CP_ACP, 0, szStr.c_str(), -1, lpwszStr, nLength );
	wszStr = lpwszStr;
	delete[] lpwszStr;
}

VOID SyscallEntry (THREADID tid, LEVEL_VM::CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
	ADDRINT syscallnum = PIN_GetSyscallNumber (ctxt, std);
	//获取系统调用号，如果是NtCreateFile，
	if (syscallnum == num_create /*&& pFileHandle == NULL*/ || syscallnum == num_open)
		/*NTSTATUS ZwCreateFile(
		_Out_     PHANDLE FileHandle,
		_In_      ACCESS_MASK DesiredAccess,
		_In_      POBJECT_ATTRIBUTES ObjectAttributes,
		_Out_     PIO_STATUS_BLOCK IoStatusBlock,
		_In_opt_  PLARGE_INTEGER AllocationSize,
		_In_      ULONG FileAttributes,
		_In_      ULONG ShareAccess,
		_In_      ULONG CreateDisposition,
		_In_      ULONG CreateOptions,
		_In_opt_  PVOID EaBuffer,
		_In_      ULONG EaLength
		);*/
	{
		WINDOWS::POBJECT_ATTRIBUTES pobj_attr
			= (WINDOWS::POBJECT_ATTRIBUTES) PIN_GetSyscallArgument (ctxt, std, 2);
		//得到打开的文件名
		wstring str = pobj_attr->ObjectName->Buffer;
		wstring str_file = str.substr (str.find_last_of ('\\') + 1);
		//判断打开的文件名与监控的污点源文件名是否相同
		if (wstrTraceFileName == str_file)
		{
			//保存文件句柄指针，并指示文件打开已完成，提示系统调用出口函数处理
			FileStatus *nstatus = new FileStatus();
			nstatus->pFileHandle = PIN_GetSyscallArgument (ctxt, std, 0);
			nstatus->JustAfterCreate = TRUE;

			FileStatusList.push_back(nstatus);
			MonitorExit = TRUE;
		}
	}
	//如果是NtReadFile
	else if (syscallnum == num_read)
		/*NTSTATUS ZwReadFile(
		_In_      HANDLE FileHandle,
		_In_opt_  HANDLE Event,
		_In_opt_  PIO_APC_ROUTINE ApcRoutine,
		_In_opt_  PVOID ApcContext,
		_Out_     PIO_STATUS_BLOCK IoStatusBlock,
		_Out_     PVOID Buffer,
		_In_      ULONG Length,
		_In_opt_  PLARGE_INTEGER ByteOffset,
		_In_opt_  PULONG Key
		);*/
	{
		for (vector<FileStatus*>::iterator i=FileStatusList.begin(); i!=FileStatusList.end(); i++)
		{
			//判断文件句柄是之前NtCreateFile得到的句柄
			if ((*i)->FileHandle && PIN_GetSyscallArgument (ctxt, std, 0) == (*i)->FileHandle)
			{
				(*i)->JustAfterRead = TRUE;
				//得到文件读入到内存中的缓冲区地址
				(*i)->InitTaintBuffer = PIN_GetSyscallArgument (ctxt, std, 5);
				//文件偏移量
				WINDOWS::PLARGE_INTEGER pByteOffset = (WINDOWS::PLARGE_INTEGER)PIN_GetSyscallArgument (ctxt, std, 7);
				if (pByteOffset!=NULL)
				{
					WINDOWS::LARGE_INTEGER ByteOffset = *pByteOffset;
					if (ByteOffset.HighPart!=-1)// || ByteOffset.LowPart!=WINDOWS::FILE_USE_FILE_POINTER_POSITION)
					{
						(*i)->FileOffset=ByteOffset;
					}
				}
				//得到读入的大小
				(*i)->pio_status = (WINDOWS::PIO_STATUS_BLOCK) (PIN_GetSyscallArgument (ctxt, std, 4) );

				MonitorExit = TRUE;
				break;
			}
		}		
	}
	else if (syscallnum == num_close)
	{
		for (vector<FileStatus*>::iterator i=FileStatusList.begin(); i!=FileStatusList.end(); i++)
		{
			if ((*i)->FileHandle && PIN_GetSyscallArgument (ctxt, std, 0) == (*i)->FileHandle)
			{
				if ((*i)->FileMappingHandle == NULL)
					FileStatusList.erase(i);
				else
					(*i)->FileHandle = NULL;
			}
			else if ((*i)->FileMappingHandle && PIN_GetSyscallArgument (ctxt, std, 0) == (*i)->FileMappingHandle)
			{
				if ((*i)->FileHandle == NULL)
					FileStatusList.erase(i);
				else
					(*i)->FileMappingHandle = NULL;
			}
			else
				continue;
			break;
		}
	}
	else if (syscallnum == num_move)
		/*NTSTATUS ZwSetInformationFile(
		_In_   HANDLE FileHandle,
		_Out_  PIO_STATUS_BLOCK IoStatusBlock,
		_In_   PVOID FileInformation,
		_In_   ULONG Length,
		_In_   FILE_INFORMATION_CLASS FileInformationClass
		);*/
	{
		for (vector<FileStatus*>::iterator i=FileStatusList.begin(); i!=FileStatusList.end(); i++)
		{
			if ((*i)->FileHandle && PIN_GetSyscallArgument (ctxt, std, 0) == (*i)->FileHandle)
			{
				if ( (WINDOWS::FILE_INFORMATION_CLASS) PIN_GetSyscallArgument (ctxt, std, 4) == WINDOWS::FilePositionInformation)
				{
					(*i)->FileOffset = ((WINDOWS::PFILE_POSITION_INFORMATION) PIN_GetSyscallArgument (ctxt, std, 2))->CurrentByteOffset;
				}
				break;
			}
		}		
	}

	else if (syscallnum == num_createsection)
		/*NTSTATUS ZwCreateSection(
		_Out_     PHANDLE SectionHandle,
		_In_      ACCESS_MASK DesiredAccess,
		_In_opt_  POBJECT_ATTRIBUTES ObjectAttributes,
		_In_opt_  PLARGE_INTEGER MaximumSize,
		_In_      ULONG SectionPageProtection,
		_In_      ULONG AllocationAttributes,
		_In_opt_  HANDLE FileHandle
		);*/
	{
		for (vector<FileStatus*>::iterator i=FileStatusList.begin(); i!=FileStatusList.end(); i++)
		{
			if ((*i)->FileHandle && PIN_GetSyscallArgument (ctxt, std, 6) == (*i)->FileHandle)
			{
				(*i)->JustAfterCreateSection = TRUE;
				(*i)->pFileMappingHandle = PIN_GetSyscallArgument (ctxt, std, 0);

				MonitorExit = TRUE;
				break;
				/*if (NULL != PIN_GetSyscallArgument (ctxt, std, 3))
					FileMappingSizeMax = *(WINDOWS::PLARGE_INTEGER)PIN_GetSyscallArgument (ctxt, std, 3);
				else
					FileMappingSizeMax.QuadPart = 0;*/
			}
		}		
	}
	else if (syscallnum == num_mapviewofsection)
		//NTSTATUS ZwMapViewOfSection(
		//_In_     HANDLE SectionHandle,
		//_In_     HANDLE ProcessHandle,
		//_Inout_  PVOID *BaseAddress,
		//_In_     ULONG_PTR ZeroBits,
		//_In_     SIZE_T CommitSize,
		//_Inout_  PLARGE_INTEGER SectionOffset,
		//_Inout_  PSIZE_T ViewSize,
		//_In_     SECTION_INHERIT InheritDisposition,
		//_In_     ULONG AllocationType,
		//_In_     ULONG Win32Protect
		//);
	{
		for (vector<FileStatus*>::iterator i=FileStatusList.begin(); i!=FileStatusList.end(); i++)
		{
			if ((*i)->FileMappingHandle && PIN_GetSyscallArgument (ctxt, std, 0) == (*i)->FileMappingHandle)
			{
				(*i)->JustAfterMapViewOfSection = TRUE;
				(*i)->pInitTaintBufferMapping = PIN_GetSyscallArgument (ctxt, std, 2);
				(*i)->pFileMappingOffset = (WINDOWS::PLARGE_INTEGER)PIN_GetSyscallArgument (ctxt, std, 5);
				(*i)->pFileMappingSize = (WINDOWS::PSIZE_T)PIN_GetSyscallArgument (ctxt, std, 6);

				MonitorExit = TRUE;
				break;
				//			FileMappingSize = *(WINDOWS::PLARGE_INTEGER)PIN_GetSyscallArgument (ctxt, std, 6);
				//			FileMappingSize = *pFileMappingSize;
			}
		}		
	}
	else if (syscallnum == num_unmapviewofsection)
		/*NTSTATUS ZwUnmapViewOfSection(
		_In_      HANDLE ProcessHandle,
		_In_opt_  PVOID BaseAddress
		);*/
	{
		for (vector<FileStatus*>::iterator i=FileStatusList.begin(); i!=FileStatusList.end(); i++)
		{
			if ((*i)->InitTaintBufferMapping && PIN_GetSyscallArgument (ctxt, std, 1) == (*i)->InitTaintBufferMapping)
			{
				GetLock(&lock, tid+1);
				string temp = "U " + hexstr((*i)->InitTaintBufferMapping,8).substr(2) + " "
					+ hexstr((UINT)((*i)->FileMappingSize)).substr(2) + "\n";
				int tlen = temp.length();
				memcpy(proc+offset, temp.c_str(), tlen);
				offset+=tlen;

				if (offset > BLOCK_SZ - TAILBLANK_SZ)
				{
//					WINDOWS::FlushViewOfFile(proc,offset);
					WINDOWS::UnmapViewOfFile(proc);

					offset_p += BLOCK_SZ;
					offset = 0;
					proc = (WINDOWS::LPBYTE)WINDOWS::MapViewOfFile(hFileMapping, FILE_MAP_WRITE,
						(WINDOWS::DWORD)(offset_p>>32),(WINDOWS::DWORD)(offset_p&0xFFFFFFFF),BLOCK_SZ);
					if (proc == NULL)
					{
						exit(0);
					}
				}
				(*i)->InitTaintBufferMapping = NULL;
				ReleaseLock(&lock);
				break;
			}
		}		
	}
}

VOID SyscallExit (THREADID tid, LEVEL_VM::CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
	if (!MonitorExit)
		return;
	for (vector<FileStatus*>::iterator i=FileStatusList.begin(); i!=FileStatusList.end(); i++)
	{
		if ((*i)->JustAfterCreate)
		{
			//根据指针得到句柄值
			(*i)->FileHandle = * (UINT32*) ((*i)->pFileHandle);
			(*i)->JustAfterCreate = FALSE;
		}
		else if ((*i)->JustAfterCreateSection)
		{
			//根据指针得到句柄值
			(*i)->FileMappingHandle = * (UINT32*) ((*i)->pFileMappingHandle);
			(*i)->JustAfterCreateSection = FALSE;
		}
		else if ((*i)->JustAfterRead)
		{
			GetLock(&lock, tid+1);
			//向日志中记录源污点数据信息
			/*if (!bActive)
			{
				int tlen = lastBBL.length();
				memcpy(proc+offset, lastBBL.c_str(), tlen);
				offset+=tlen;
			}*/

			string temp = "T " + hexstr((*i)->InitTaintBuffer,8).substr(2) + " "
				+ hexstr((*i)->FileOffset.QuadPart).substr(2) + " " + hexstr((UINT32)((*i)->pio_status->Information)).substr(2) + "\n";
			int tlen = temp.length();
			memcpy(proc+offset, temp.c_str(), tlen);
			offset+=tlen;

			if (offset > BLOCK_SZ - TAILBLANK_SZ)
			{
//				WINDOWS::FlushViewOfFile(proc,offset);
				WINDOWS::UnmapViewOfFile(proc);

				offset_p += BLOCK_SZ;
				offset = 0;
				proc = (WINDOWS::LPBYTE)WINDOWS::MapViewOfFile(hFileMapping, FILE_MAP_WRITE,
					(WINDOWS::DWORD)(offset_p>>32),(WINDOWS::DWORD)(offset_p&0xFFFFFFFF),BLOCK_SZ);
				if (proc == NULL)
				{
					exit(0);
				}
			}

			(*i)->FileOffset.QuadPart+=(*i)->pio_status->Information;
			(*i)->JustAfterRead = FALSE;
//			bActive = TRUE;
			if (!bActive)
			{
				PIN_RemoveInstrumentation();
				bActive = TRUE;
			}
			ReleaseLock(&lock);
		}
		else if ((*i)->JustAfterMapViewOfSection)
		{
			GetLock(&lock, tid+1);
			/*if (!bActive)
			{
				int tlen = lastBBL.length();
				memcpy(proc+offset, lastBBL.c_str(), tlen);
				offset+=tlen;
			}*/
			(*i)->InitTaintBufferMapping = *(ADDRINT*) ((*i)->pInitTaintBufferMapping);
			(*i)->FileMappingOffset = *((*i)->pFileMappingOffset);

	//		WINDOWS::LARGE_INTEGER FileMappingSizeReal = *pFileMappingSize;
	//		if (FileMappingSize.QuadPart == 0)
	//			FileMappingSize = FileMappingSizeMax;
			(*i)->FileMappingSize = *((*i)->pFileMappingSize);

			string temp = "T " + hexstr((*i)->InitTaintBufferMapping,8).substr(2) + " "
				+ hexstr((*i)->FileMappingOffset.QuadPart).substr(2) + " " + hexstr((UINT)((*i)->FileMappingSize)).substr(2) + "\n";
			int tlen = temp.length();
			memcpy(proc+offset, temp.c_str(), tlen);
			offset+=tlen;

			if (offset > BLOCK_SZ - TAILBLANK_SZ)
			{
//				WINDOWS::FlushViewOfFile(proc,offset);
				WINDOWS::UnmapViewOfFile(proc);

				offset_p += BLOCK_SZ;
				offset = 0;
				proc = (WINDOWS::LPBYTE)WINDOWS::MapViewOfFile(hFileMapping, FILE_MAP_WRITE,
					(WINDOWS::DWORD)(offset_p>>32),(WINDOWS::DWORD)(offset_p&0xFFFFFFFF),BLOCK_SZ);
				if (proc == NULL)
				{
					exit(0);
				}
			}

			(*i)->JustAfterMapViewOfSection = FALSE;
//			bActive = TRUE;
			if (!bActive)
			{
				PIN_RemoveInstrumentation();
				bActive = TRUE;
			}
			ReleaseLock(&lock);
		}
		else
			continue;
		break;
	}
	MonitorExit = FALSE;
}