#include "pin.H"
#include <string>
#include <vector>
#include <set>
#define BLOCK_SZ 0x20000000
#define TAILBLANK_SZ 1024
//#define LOGTIME

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

extern ofstream fOutput1;
extern WINDOWS::LPBYTE proc;
extern WINDOWS::HANDLE hFileMapping;
extern WINDOWS::DWORD offset;
extern unsigned __int64 offset_p;
LEVEL_BASE::BOOL bActive = FALSE;	//插装启动标志
extern PIN_LOCK lock;
extern THREADID CurTid;
extern set<UINT> InstTid;
//extern string lastBBL;
#ifdef LOGTIME
extern WINDOWS::SYSTEMTIME StartTime;
#endif

//监视文件打开相关系统调用的变量
UINT num_create = 0, num_open = 0, num_read = 0, num_close = 0, num_move = 0;
UINT num_createsection = 0, num_mapviewofsection = 0, num_unmapviewofsection = 0;
UINT num_allocmem = 0, num_freemem = 0;
UINT num_create_64 = 0, num_open_64 = 0, num_read_64 = 0, num_close_64 = 0, num_move_64 = 0;
UINT num_createsection_64 = 0, num_mapviewofsection_64 = 0, num_unmapviewofsection_64 = 0;
UINT num_allocmem_64 = 0, num_freemem_64 = 0;
wstring wstrTraceFileName;
LEVEL_BASE::BOOL MonitorExit = FALSE;
BOOL JustAfterVMem = FALSE;
ADDRINT* VMemBaseAddr = 0;
UINT* VMemSize = 0;


class FileStatus
{
public:
	UINT32 pFileHandle;							//文件句柄指针
	UINT32 FileHandle;							//文件句柄
	UINT32 pFileMappingHandle;					//文件Mapping句柄指针
	UINT32 FileMappingHandle;					//文件Mapping句柄
	LEVEL_BASE::BOOL JustAfterCreate;			//标记量-创建
	LEVEL_BASE::BOOL JustAfterRead;				//标记量-读取
	LEVEL_BASE::BOOL JustAfterCreateSection;	//标记量-创建Section
	LEVEL_BASE::BOOL JustAfterMapViewOfSection;	//标记量-创建MapView
	WINDOWS::PIO_STATUS_BLOCK pio_status;		//状态结构，内含文件大小信息
	ADDRINT InitTaintBuffer;					//文件缓冲区地址
	ADDRINT InitTaintBufferMapping;				//文件Mapping缓冲区地址
	ADDRINT pInitTaintBufferMapping;			//文件Mapping缓冲区地址指针	
	WINDOWS::LARGE_INTEGER FileOffset;			//文件偏移量
	WINDOWS::LARGE_INTEGER FileMappingOffset;	//文件Mapping偏移量
	WINDOWS::PLARGE_INTEGER pFileMappingOffset;	//文件Mapping偏移量
	WINDOWS::SIZE_T FileMappingSize;			//文件Mapping大小
	WINDOWS::PSIZE_T pFileMappingSize;			//文件Mapping大小指针

	//偏移量、文件大小和缓冲区地址的关系：
	//系统将从文件偏移量（offset）处的（Size）文件大小的内容读入缓冲区地址（TaintBuffer）

	/*构造函数*/
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
	if (!InstTid.empty() && InstTid.count(tid)==0)
		return;
	ADDRINT syscallnum = PIN_GetSyscallNumber (ctxt, std);
	//获取系统调用号，如果是NtCreateFile，
	if (std==SYSCALL_STANDARD_IA32_WINDOWS_FAST && (syscallnum == num_create /*&& pFileHandle == NULL*/ || syscallnum == num_open)
		|| std==SYSCALL_STANDARD_WOW64 && (syscallnum == num_create_64 /*&& pFileHandle == NULL*/ || syscallnum == num_open_64))
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
	else if (std==SYSCALL_STANDARD_IA32_WINDOWS_FAST && syscallnum == num_read
		|| std==SYSCALL_STANDARD_WOW64 && syscallnum == num_read_64)
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
		UINT fHandleNum=FileStatusList.size();
		bool IsTgt=false;
//		for (vector<FileStatus*>::iterator i=FileStatusList.begin(); i!=FileStatusList.end(); i++)
		for (UINT ti=0; ti!=fHandleNum; ++ti)
		{
			FileStatus* tFileStatus=FileStatusList[ti];
			//判断文件句柄是之前NtCreateFile得到的句柄
			if (tFileStatus->FileHandle && PIN_GetSyscallArgument (ctxt, std, 0) == tFileStatus->FileHandle)
			{
				tFileStatus->JustAfterRead = TRUE;
				//得到文件读入到内存中的缓冲区地址
				tFileStatus->InitTaintBuffer = PIN_GetSyscallArgument (ctxt, std, 5);
				//得到指向文件偏移量的指针
				WINDOWS::PLARGE_INTEGER pByteOffset = (WINDOWS::PLARGE_INTEGER)PIN_GetSyscallArgument (ctxt, std, 7);
				if (pByteOffset!=NULL)
				{
					WINDOWS::LARGE_INTEGER ByteOffset = *pByteOffset;
					if (ByteOffset.HighPart!=-1)// || ByteOffset.LowPart!=WINDOWS::FILE_USE_FILE_POINTER_POSITION)
					{
						tFileStatus->FileOffset=ByteOffset;
					}
				}
				//得到指向读入的大小结构指针
				tFileStatus->pio_status = (WINDOWS::PIO_STATUS_BLOCK) (PIN_GetSyscallArgument (ctxt, std, 4) );

				MonitorExit = TRUE;
				IsTgt=true;
				break;
			}
		}
		if (!IsTgt)
		{
			PIN_GetLock(&lock, tid+1);
			string temp = "U " + hexstr(PIN_GetSyscallArgument (ctxt, std, 5),8).substr(2) + " "
				+ hexstr(PIN_GetSyscallArgument (ctxt, std, 6)).substr(2) + "\n";
			int tlen = temp.length();
			memcpy(proc+offset, temp.c_str(), tlen);
			offset+=tlen;

			//若当前内存映射文件大小越界，则重新创建内存映射文件
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
			PIN_ReleaseLock(&lock);
		}
	}
	//如果是文件关闭调用
	else if (std==SYSCALL_STANDARD_IA32_WINDOWS_FAST && syscallnum == num_close
		|| std==SYSCALL_STANDARD_WOW64 && syscallnum == num_close_64)
	{
		UINT fHandleNum=FileStatusList.size();
//		for (vector<FileStatus*>::iterator i=FileStatusList.begin(); i!=FileStatusList.end(); i++)
		for (UINT ti=0; ti!=fHandleNum; ++ti)
		{
			FileStatus* tFileStatus=FileStatusList[ti];
			//判断文件句柄是之前NtCreateFile得到的句柄
			if (tFileStatus->FileHandle && PIN_GetSyscallArgument (ctxt, std, 0) == tFileStatus->FileHandle)
			{
				//删除文件句柄
				if (tFileStatus->FileMappingHandle == NULL)
					FileStatusList.erase(FileStatusList.begin()+ti);
				else
					tFileStatus->FileHandle = NULL;
			}
			//判断Mapping文件句柄是之前NtCreateSection得到的句柄
			else if (tFileStatus->FileMappingHandle && PIN_GetSyscallArgument (ctxt, std, 0) == tFileStatus->FileMappingHandle)
			{
				//删除Maping文件句柄
				if (tFileStatus->FileHandle == NULL)
					FileStatusList.erase(FileStatusList.begin()+ti);
				else
					tFileStatus->FileMappingHandle = NULL;
			}
			else
				continue;
			break;
		}
	}
	//如果是文件移动调用
	else if (std==SYSCALL_STANDARD_IA32_WINDOWS_FAST && syscallnum == num_move
		|| std==SYSCALL_STANDARD_WOW64 && syscallnum == num_move_64)
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
			//判断文件句柄是之前NtCreateFile得到的句柄
			if ((*i)->FileHandle && PIN_GetSyscallArgument (ctxt, std, 0) == (*i)->FileHandle)
			{
				//得到新的文件偏移量
				if ( (WINDOWS::FILE_INFORMATION_CLASS) PIN_GetSyscallArgument (ctxt, std, 4) == WINDOWS::FilePositionInformation)
				{
					(*i)->FileOffset = ((WINDOWS::PFILE_POSITION_INFORMATION) PIN_GetSyscallArgument (ctxt, std, 2))->CurrentByteOffset;
				}
				break;
			}
		}		
	}
	//如果是CreateSection
	else if (std==SYSCALL_STANDARD_IA32_WINDOWS_FAST && syscallnum == num_createsection
		|| std==SYSCALL_STANDARD_WOW64 && syscallnum == num_createsection_64)
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
			//判断文件句柄是之前NtCreateFile得到的句柄
			if ((*i)->FileHandle && PIN_GetSyscallArgument (ctxt, std, 6) == (*i)->FileHandle)
			{
				//存储Mapping文件句柄
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
	//如果是MapViewOfSection
	else if (std==SYSCALL_STANDARD_IA32_WINDOWS_FAST && syscallnum == num_mapviewofsection
		|| std==SYSCALL_STANDARD_WOW64 && syscallnum == num_mapviewofsection_64)
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
		bool IsTgt=false;
		for (vector<FileStatus*>::iterator i=FileStatusList.begin(); i!=FileStatusList.end(); i++)
		{
			//判断Mapping文件句柄是之前CreateSection得到的句柄
			if ((*i)->FileMappingHandle && PIN_GetSyscallArgument (ctxt, std, 0) == (*i)->FileMappingHandle)
			{
				(*i)->JustAfterMapViewOfSection = TRUE;
				//得到指向文件读入到内存中的缓冲区地址的指针
				(*i)->pInitTaintBufferMapping = PIN_GetSyscallArgument (ctxt, std, 2);
				//得到指向文件偏移量的指针
				(*i)->pFileMappingOffset = (WINDOWS::PLARGE_INTEGER)PIN_GetSyscallArgument (ctxt, std, 5);
				//得到指向Mapping大小的指针
				(*i)->pFileMappingSize = (WINDOWS::PSIZE_T)PIN_GetSyscallArgument (ctxt, std, 6);

				MonitorExit = TRUE;
				IsTgt=true;
				break;
				//			FileMappingSize = *(WINDOWS::PLARGE_INTEGER)PIN_GetSyscallArgument (ctxt, std, 6);
				//			FileMappingSize = *pFileMappingSize;
			}
		}
		if (!IsTgt)
		{
			PIN_GetLock(&lock, tid+1);
			string temp = "U " + hexstr(PIN_GetSyscallArgument (ctxt, std, 2),8).substr(2) + " "
				+ hexstr(PIN_GetSyscallArgument (ctxt, std, 6)).substr(2) + "\n";
			int tlen = temp.length();
			memcpy(proc+offset, temp.c_str(), tlen);
			offset+=tlen;

			//若当前内存映射文件大小越界，则重新创建内存映射文件
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
			PIN_ReleaseLock(&lock);
		}
	}
	//如果是UmMapViewOfSection
	else if (std==SYSCALL_STANDARD_IA32_WINDOWS_FAST && syscallnum == num_unmapviewofsection
		|| std==SYSCALL_STANDARD_WOW64 && syscallnum == num_unmapviewofsection_64)
		/*NTSTATUS ZwUnmapViewOfSection(
		_In_      HANDLE ProcessHandle,
		_In_opt_  PVOID BaseAddress
		);*/
	{
		for (vector<FileStatus*>::iterator i=FileStatusList.begin(); i!=FileStatusList.end(); i++)
		{
			//判断缓冲区地址是之前MapViewOfSection得到的地址
			if ((*i)->InitTaintBufferMapping && PIN_GetSyscallArgument (ctxt, std, 1) == (*i)->InitTaintBufferMapping)
			{
				PIN_GetLock(&lock, tid+1);
				string temp = "U " + hexstr((*i)->InitTaintBufferMapping,8).substr(2) + " "
					+ hexstr((UINT)((*i)->FileMappingSize)).substr(2) + "\n";
				int tlen = temp.length();
				memcpy(proc+offset, temp.c_str(), tlen);
				offset+=tlen;

				//若当前内存映射文件大小越界，则重新创建内存映射文件
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
				//删除缓冲区地址信息
				(*i)->InitTaintBufferMapping = NULL;
				PIN_ReleaseLock(&lock);
				break;
			}
		}		
	}
	//如果是Allocate/Free VirtualMemory
	else if (std==SYSCALL_STANDARD_IA32_WINDOWS_FAST && syscallnum == num_allocmem
		|| std==SYSCALL_STANDARD_WOW64 && syscallnum == num_allocmem_64)
	{
		JustAfterVMem = TRUE;
		VMemBaseAddr = (ADDRINT*)PIN_GetSyscallArgument (ctxt, std, 1);
		VMemSize = (UINT*)PIN_GetSyscallArgument (ctxt, std, 3);
		MonitorExit = TRUE;
	}
	else if (syscallnum==num_freemem)
	{
		JustAfterVMem = TRUE;
		VMemBaseAddr = (ADDRINT*)PIN_GetSyscallArgument (ctxt, std, 1);
		VMemSize = (UINT*)PIN_GetSyscallArgument (ctxt, std, 2);
		MonitorExit = TRUE;
	}
}

VOID SyscallExit (THREADID tid, LEVEL_VM::CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
	if (!MonitorExit)
		return;
	if (JustAfterVMem)
	{
		PIN_GetLock(&lock, tid+1);
		string temp = "U " + hexstr(*VMemBaseAddr,8).substr(2) + " "
			+ hexstr(*VMemSize).substr(2) + "\n";
		int tlen = temp.length();
		memcpy(proc+offset, temp.c_str(), tlen);
		offset+=tlen;

		//若当前内存映射文件大小越界，则重新创建内存映射文件
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
		PIN_ReleaseLock(&lock);
		MonitorExit=FALSE;
		JustAfterVMem=FALSE;
		return;
	}
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
			PIN_GetLock(&lock, tid+1);
			//向日志中记录源污点数据信息
			/*if (!bActive)
			{
				int tlen = lastBBL.length();
				memcpy(proc+offset, lastBBL.c_str(), tlen);
				offset+=tlen;
			}*/

			//输出缓冲区地址、偏移量和文件大小到日志
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

			//开始Trace插装
			if (!bActive)
			{
				PIN_RemoveInstrumentation();
#ifdef LOGTIME
				WINDOWS::GetLocalTime(&StartTime);
#endif
				bActive = TRUE;
			}
			PIN_ReleaseLock(&lock);
		}
		else if ((*i)->JustAfterMapViewOfSection)
		{
			PIN_GetLock(&lock, tid+1);
			//向日志中记录源污点数据信息
			/*if (!bActive)
			{
				int tlen = lastBBL.length();
				memcpy(proc+offset, lastBBL.c_str(), tlen);
				offset+=tlen;
			}*/
			//根据指针得到缓冲区大小和偏移量
			(*i)->InitTaintBufferMapping = *(ADDRINT*) ((*i)->pInitTaintBufferMapping);
			(*i)->FileMappingOffset = *((*i)->pFileMappingOffset);

	//		WINDOWS::LARGE_INTEGER FileMappingSizeReal = *pFileMappingSize;
	//		if (FileMappingSize.QuadPart == 0)
	//			FileMappingSize = FileMappingSizeMax;
			//根据指针得到文件Mapping大小
			(*i)->FileMappingSize = *((*i)->pFileMappingSize);

			//输出缓冲区地址、偏移量和文件大小到日志
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
#ifdef LOGTIME
				WINDOWS::GetLocalTime(&StartTime);
#endif
				bActive = TRUE;
			}
			PIN_ReleaseLock(&lock);
		}
		else
			continue;
		break;
	}
	MonitorExit = FALSE;
}