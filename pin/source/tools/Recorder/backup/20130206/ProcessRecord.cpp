#include <iostream>
#include <fstream>
#include "pin.H"
#include "SystemCall.h"

#define BLOCK_SZ 0x20000000
#define TAILBLANK_SZ 0x15

KNOB<string> KnobOutputPath (KNOB_MODE_APPEND, "pintool", "op", "", "specify directory path for output");
KNOB<string> KnobTraceFile (KNOB_MODE_WRITEONCE, "pintool", "tf", "", "specify file name for trace");
KNOB<BOOL>   KnobPrintMem(KNOB_MODE_WRITEONCE, "pintool", "m", "1", "print memory addr");
KNOB<UINT>   KnobMaxLogSize(KNOB_MODE_WRITEONCE, "pintool", "logsz", "10", "maximum logfile size");

static ofstream fOutput1;
//static ofstream fOutput2;
WINDOWS::LPBYTE proc;
WINDOWS::LPBYTE bbllist;
//__int64 offset = 0;
WINDOWS::DWORD offset = 0;
unsigned __int64 offset_p = 0;
unsigned __int64 offset_list = 0;
WINDOWS::HANDLE hFile;
WINDOWS::HANDLE hFileMapping;
WINDOWS::HANDLE hFile_list;
WINDOWS::HANDLE hFileMapping_list;

UINT32 IndexBBL = 0;
PIN_LOCK lock;
THREADID CurTid = 0xffffffff;
//ADDRINT EspEbpTable[2][100];
ADDRINT StackBaseTable[200];
ADDRINT CurThreadStackBase;

//string lastBBL;

UINT32 User32ID = 0;
unsigned __int64 CountBBL = 0;

static UINT Usage (void)
{
	cerr << "This PINTOOL is used to record all instructions executed." << endl;
	cerr << KNOB_BASE::StringKnobSummary() << endl;
	return -1;
}

VOID Fini (INT32 code, VOID *v)
{
	fOutput1.close();
	
	string temp = decstr(CountBBL)+"\r\n";
	int tlen = temp.length();
	memcpy(bbllist+offset_list, temp.c_str(), tlen);
	offset_list+=tlen;

	WINDOWS::UnmapViewOfFile(bbllist);
	WINDOWS::CloseHandle(hFileMapping_list);
	WINDOWS::LONG HighOffset = (WINDOWS::LONG)(offset_list>>32);
	WINDOWS::SetFilePointer(hFile_list,(UINT32)(offset_list&0xFFFFFFFF),&HighOffset,FILE_BEGIN);
	WINDOWS::SetEndOfFile(hFile_list);
	WINDOWS::CloseHandle(hFile_list);

	WINDOWS::UnmapViewOfFile(proc);
	WINDOWS::CloseHandle(hFileMapping);
	offset_p += offset;
	WINDOWS::LONG HighOffset2 = (WINDOWS::LONG)(offset_p>>32);
	WINDOWS::SetFilePointer(hFile,(UINT32)(offset_p&0xFFFFFFFF),&HighOffset2,FILE_BEGIN);
	WINDOWS::SetEndOfFile(hFile);
	WINDOWS::CloseHandle(hFile);
}

VOID ImageLoad (IMG img, VOID *)
{
	string img_file = IMG_Name (img).substr (IMG_Name (img).find_last_of ('\\') + 1);
	int i = img_file.find(' ');
	if (i != string::npos)
		img_file[i]='_';
	fOutput1 << "Image " << img_file << " " << hex << IMG_LowAddress (img) << " " << IMG_HighAddress (img)
	         << dec << " ID: " << IMG_Id (img) << endl;
//	if (img_file == "USER32.dll" || img_file == "user32.dll")
//	{
//		User32ID = IMG_Id (img);
//	}
}

VOID PIN_FAST_ANALYSIS_CALL EnterBBL (UINT32 index, UINT32 ImgID, THREADID threadid/*, ADDRINT espv, ADDRINT ebpv*/)
{
//	if (bActive)
//	{
	GetLock (&lock, threadid + 1);
	++CountBBL;
	/*string temp;
	if (threadid != CurTid)
	{
		CurTid = threadid;
		temp = decstr(threadid) + " ";
	}
	temp += "B " + hexstr(index).substr(2) + "\n";
	int tlen = temp.length();
	memcpy(proc+offset, temp.c_str(), tlen);
	offset+=tlen;*/
	if (threadid != CurTid)
	{
		CurTid = threadid;
//		sprintf((char*)proc+offset,"%d ",threadid);
//		offset+=(threadid<10?2:(threadid<100?3:4));
		_itoa(threadid,(char*)proc+offset,10);
		offset+=(threadid<10?2:(threadid<100?3:4));
		*(proc+offset-1)=' ';
		CurThreadStackBase=StackBaseTable[threadid];
	}
	/*offset+=sprintf((char*)proc+offset,"B %x",index);
	if (EspEbpTable[0][threadid]!=espv || EspEbpTable[1][threadid]!=ebpv)
	{
		offset+=sprintf((char*)proc+offset," %d %d",espv-EspEbpTable[0][threadid],ebpv-EspEbpTable[1][threadid]);
		EspEbpTable[0][threadid]=espv;
		EspEbpTable[1][threadid]=ebpv;
	}
	*(proc+(offset++))='\n';*/
	*(proc+offset)='B';
	*(proc+(++offset))=' ';
	++offset;
	_itoa(index,(char*)proc+offset,16);
//	offset+=(index<0x10?2:(index<0x100?3:(index<0x1000?4:(index<0x10000?5:(index<0x100000?6:(index<0x1000000?7:8))))));
	offset+=(index<0x10000?(index<0x100?(index<0x10?2:3):(index<0x1000?4:5)):(index<0x1000000?(index<0x100000?6:7):8));
	*(proc+offset-1)='\n';

	if (offset > BLOCK_SZ - TAILBLANK_SZ)
	{
		WINDOWS::UnmapViewOfFile(proc);

		offset_p += BLOCK_SZ;
		offset = 0;
		proc = (WINDOWS::LPBYTE)WINDOWS::MapViewOfFile(hFileMapping, FILE_MAP_WRITE,
			(WINDOWS::DWORD)(offset_p>>32),(WINDOWS::DWORD)(offset_p&0xFFFFFFFF),BLOCK_SZ);
		if (proc == NULL)
		{
			fOutput1 << "FileMapping Failed 2!";
			fOutput1.close();
			exit(0);
		}
	}

	ReleaseLock (&lock);
//	}
	/*else if (ImgID == 1)
	{
		lastBBL = decstr(threadid) + " B " + hexstr(index).substr(2) + "\n";
	}*/
}

//VOID TerminateAnalysis()
//{
//	PIN_Detach();
////	bActive = FALSE;
////	fOutput2 << "Instrumentation terminated!" << endl;
//}
//
//VOID PIN_FAST_ANALYSIS_CALL SkipAnalysis (THREADID threadid)
//{
//	if (bActive)
//	{
//		//根据线程TID获取互斥锁
//		GetLock (&lock, threadid + 1);
////		fOutput2 << "SKIP" << endl;
//		//释放锁
//		ReleaseLock (&lock);
//	}
//}

VOID PIN_FAST_ANALYSIS_CALL PrintMemAddr (ADDRINT addr, THREADID threadid/*, BOOL read*/)
{
//	if (bActive)
//	{
	//根据线程TID获取互斥锁
	GetLock (&lock, threadid + 1);
//	fOutput2 << "T" << threadid << (read ? " R " : " W ") << hex << addr << dec << endl;
	/*string temp;
	if (threadid != CurTid)
	{
		CurTid = threadid;
		temp = decstr(threadid) + " ";
	}
	temp += hexstr(addr).substr(2) + "\n";
	int tlen = temp.length();
	memcpy(proc+offset, temp.c_str(), tlen);
	offset+=tlen;*/
	if (threadid != CurTid)
	{
		CurTid = threadid;
//		sprintf((char*)proc+offset,"%d ",threadid);
		_itoa(threadid,(char*)proc+offset,10);
		offset+=(threadid<10?2:(threadid<100?3:4));
		*(proc+offset-1)=' ';
		CurThreadStackBase=StackBaseTable[threadid];
	}
//	offset+=sprintf((char*)proc+offset,"%x\n",addr);
	_itoa(addr,(char*)proc+offset,16);
	offset+=(addr>=0x10000000?9:(addr>=0x1000000?8:(addr>=0x100000?7:(addr>=0x10000?6:(addr>=0x1000?5:4)))));
	*(proc+offset-1)='\n';

	if (offset > BLOCK_SZ - TAILBLANK_SZ)
	{
		WINDOWS::UnmapViewOfFile(proc);

		offset_p += BLOCK_SZ;
		offset = 0;
		proc = (WINDOWS::LPBYTE)WINDOWS::MapViewOfFile(hFileMapping, FILE_MAP_WRITE,
			(WINDOWS::DWORD)(offset_p>>32),(WINDOWS::DWORD)(offset_p&0xFFFFFFFF),BLOCK_SZ);
		if (proc == NULL)
		{
			fOutput1 << "FileMapping Failed 2!";
			fOutput1.close();
			exit(0);
		}
	}

	//释放锁
	ReleaseLock (&lock);
//	}
}

VOID PIN_FAST_ANALYSIS_CALL PrintStackAddr (ADDRINT addr, THREADID threadid)
{
	GetLock (&lock, threadid + 1);
	if (threadid != CurTid)
	{
		CurTid = threadid;
		_itoa(threadid,(char*)proc+offset,10);
		offset+=(threadid<10?2:(threadid<100?3:4));
		*(proc+offset-1)=' ';
		CurThreadStackBase=StackBaseTable[threadid];
	}
//	addr=StackBaseTable[threadid]-addr;
	addr=CurThreadStackBase-addr;
	_itoa(addr,(char*)proc+offset,16);
	offset+=(addr>=0x100?(addr>=0x1000?(addr>=0x10000?6:5):4):(addr>=0x10?3:2));
	*(proc+offset-1)='\n';

	if (offset > BLOCK_SZ - TAILBLANK_SZ)
	{
		WINDOWS::UnmapViewOfFile(proc);

		offset_p += BLOCK_SZ;
		offset = 0;
		proc = (WINDOWS::LPBYTE)WINDOWS::MapViewOfFile(hFileMapping, FILE_MAP_WRITE,
			(WINDOWS::DWORD)(offset_p>>32),(WINDOWS::DWORD)(offset_p&0xFFFFFFFF),BLOCK_SZ);
		if (proc == NULL)
		{
			fOutput1 << "FileMapping Failed 2!";
			fOutput1.close();
			exit(0);
		}
	}
	ReleaseLock (&lock);
}

VOID Trace (TRACE trace, VOID *v)
{
	if (!bActive)
		return;
	//获得当前Trace隶属的函数的函数名
	RTN rtn = TRACE_Rtn (trace);
	string RtnName = "";
	if (RTN_Valid (rtn) )
		RtnName = RTN_Name (rtn);
	//有的代码存在于dll未导出的内部函数中，无法获得函数名
	else
		RtnName = "InvalidRTN";

	UINT32 ImgID = IMG_Id (IMG_FindByAddress (TRACE_Address (trace) ) );
/*
	//检查当前Trace所在的函数是否是消息循环函数
	if (ImgID == User32ID)
	{
		if (RtnName.find ("Message") != string::npos)
		{
			if (RtnName.find ("GetMessage") != string::npos
			        || RtnName.find ("SendMessage") != string::npos
			        || RtnName.find ("PeekMessage") != string::npos
			        || RtnName.find ("PostMessage") != string::npos
			        || RtnName.find ("WaitMessage") != string::npos
			        || RtnName.find ("TranslateMessage") != string::npos
			        || RtnName.find ("DispatchMessage") != string::npos
			        || RtnName.find ("ReplyMessage") != string::npos
			        || RtnName.find ("SetMessage") != string::npos
			        || RtnName.find ("BroadcastSystemMessage") != string::npos
			        || RtnName.find ("PostQuitMessage") != string::npos
			        || RtnName.find ("PostThreadMessage") != string::npos
					|| RtnName.find ("RegisterWindowMessage") != string::npos
					|| RtnName.find ("SendNotifyMessage") != string::npos)
					{
					TRACE_InsertCall (trace, IPOINT_ANYWHERE, (AFUNPTR) SkipAnalysis, IARG_FAST_ANALYSIS_CALL,
				                  IARG_THREAD_ID, IARG_END);
				return;
			}
		}
		else if (RtnName == "GetInputState" || RtnName == "GetQueueStatus")
		{
			TRACE_InsertCall (trace, IPOINT_ANYWHERE, (AFUNPTR) SkipAnalysis, IARG_FAST_ANALYSIS_CALL,
			                  IARG_THREAD_ID, IARG_END);
			return;
		}
	}

*/

//	if (RtnName.find ("CriticalSection") != string::npos || RtnName == "GetCurrentThreadId" 
//		|| RtnName == "TlsGetValue" || RtnName == "SetLastError" || RtnName == "GetLastError")
/*	if (ImgID != 1)
	{
		TRACE_InsertCall (trace, IPOINT_ANYWHERE, (AFUNPTR) SkipAnalysis, IARG_FAST_ANALYSIS_CALL,
			IARG_THREAD_ID, IARG_END);
		return;
	}
	*/
	// 遍历Trace中的所有BBL
	for (BBL bbl = TRACE_BblHead (trace); BBL_Valid (bbl); bbl = BBL_Next (bbl) )
	{
		//给定当前顺序分配的一个索引号，并记录到日志文件中
//		fOutput1 << "BBL " << hexstr(++IndexBBL).substr(2) << "\n" << ImgID << " " << RtnName << endl;
		string temp = "BBL "+hexstr(++IndexBBL).substr(2)+"\n"+decstr(ImgID)+" "+RtnName+"\n";
		int tlen = temp.length();
		memcpy(bbllist+offset_list, temp.data(), tlen);
		offset_list+=tlen;

		// 对该BBL插装，用于在后续执行该BBL序列时打印调用记录
		BBL_InsertCall (bbl, IPOINT_BEFORE, (AFUNPTR) EnterBBL, IARG_FAST_ANALYSIS_CALL,
						IARG_UINT32, IndexBBL, IARG_UINT32, ImgID, IARG_THREAD_ID,
						/*IARG_REG_VALUE, REG_ESP, IARG_REG_VALUE, REG_EBP,*/ IARG_END);

		int memcount = 0;
		//遍历BBL中所有指令
		for (INS ins = BBL_InsHead (bbl); INS_Valid (ins); ins = INS_Next (ins) )
		{
			//记录指令地址与反汇编代码
//			fOutput1 << hexstr(INS_Address (ins),8) << " " << INS_Disassemble (ins) << endl;
			string temp = hexstr(INS_Address (ins),8)+" "+INS_Disassemble (ins)+"\n";
			int tlen = temp.length();
			memcpy(bbllist+offset_list, temp.data(), tlen);
			offset_list+=tlen;

			if (KnobPrintMem.Value())
			{
//				BOOL ss = INS_IsStackRead(ins) || INS_IsStackWrite(ins);
				if (INS_IsStackRead(ins))
				{
					string temp = "r"+decstr(++memcount)+"\n";
					int tlen = memcount<10?3:(memcount<100?4:5);
					memcpy(bbllist+offset_list, temp.data(), tlen);
					offset_list+=tlen;
					INS_InsertPredicatedCall (ins, IPOINT_BEFORE, (AFUNPTR) PrintStackAddr, IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYREAD_EA, IARG_THREAD_ID,/* IARG_BOOL, TRUE,*/ IARG_END);
				}
				else if (INS_IsMemoryRead (ins) )
				{
					string temp = "R"+decstr(++memcount)+"\n";
					int tlen = memcount<10?3:(memcount<100?4:5);
					memcpy(bbllist+offset_list, temp.data(), tlen);
					offset_list+=tlen;
					INS_InsertPredicatedCall (ins, IPOINT_BEFORE, (AFUNPTR) PrintMemAddr, IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYREAD_EA, IARG_THREAD_ID,/* IARG_BOOL, TRUE,*/ IARG_END);
				}
				if (INS_HasMemoryRead2 (ins) )
				{
					string temp = "R"+decstr(++memcount)+"\n";
					int tlen = memcount<10?3:(memcount<100?4:5);
					memcpy(bbllist+offset_list, temp.data(), tlen);
					offset_list+=tlen;
					INS_InsertPredicatedCall (ins, IPOINT_BEFORE, (AFUNPTR) PrintMemAddr, IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYREAD2_EA, IARG_THREAD_ID,/* IARG_BOOL, TRUE,*/ IARG_END);
				}
				if (INS_IsStackWrite(ins))
				{
					string temp = "w"+decstr(++memcount)+"\n";
					int tlen = memcount<10?3:(memcount<100?4:5);
					memcpy(bbllist+offset_list, temp.data(), tlen);
					offset_list+=tlen;
					INS_InsertPredicatedCall (ins, IPOINT_BEFORE, (AFUNPTR) PrintStackAddr, IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA, IARG_THREAD_ID,/* IARG_BOOL, FALSE,*/ IARG_END);
				}
				else if (INS_IsMemoryWrite (ins) )
				{
					string temp = "W"+decstr(++memcount)+"\n";
					int tlen = memcount<10?3:(memcount<100?4:5);
					memcpy(bbllist+offset_list, temp.data(), tlen);
					offset_list+=tlen;
					INS_InsertPredicatedCall (ins, IPOINT_BEFORE, (AFUNPTR) PrintMemAddr, IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA, IARG_THREAD_ID,/* IARG_BOOL, FALSE,*/ IARG_END);
				}

				//UINT32 memOperands = INS_MemoryOperandCount(ins);
				//for (UINT32 memOp = 0; memOp < memOperands; memOp++)
				//{
				//	if (INS_MemoryOperandIsRead(ins, memOp))
				//	{
				//		string temp("R");
				//		if (ss)
				//			temp += "0";
				//		else
				//		{
				//			INS_InsertPredicatedCall (ins, IPOINT_BEFORE, (AFUNPTR) PrintMemAddr, IARG_FAST_ANALYSIS_CALL,
				//				IARG_MEMORYOP_EA, memOp, IARG_THREAD_ID, IARG_END);
				//			temp += decstr(++memcount);
				//		}
				//		temp += "\n";
				//		int tlen = temp.length();
				//		memcpy(bbllist+offset_list, temp.c_str(), tlen);
				//		offset_list+=tlen;
				//	}
				//	if (INS_MemoryOperandIsWritten(ins, memOp))
				//	{
				//		string temp("W");
				//		if (ss)
				//			temp += "0";
				//		else
				//		{
				//			INS_InsertPredicatedCall (ins, IPOINT_BEFORE, (AFUNPTR) PrintMemAddr, IARG_FAST_ANALYSIS_CALL,
				//				IARG_MEMORYOP_EA, memOp, IARG_THREAD_ID, IARG_END);
				//			temp += decstr(++memcount);
				//		}
				//		temp += "\n";
				//		int tlen = temp.length();
				//		memcpy(bbllist+offset_list, temp.c_str(), tlen);
				//		offset_list+=tlen;
				//	}
				//}
			}			
		}

//		fOutput1 << "0" << endl;
		memcpy(bbllist+offset_list, "0\n", 2);
		offset_list+=2;
	}
}

// This routine is executed every time a thread is created.
VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
//	fOutput1 << "Thread " << threadid << "started, ESP=" << PIN_GetContextReg(ctxt,REG_ESP) 
	//		<< ", EBP=" << PIN_GetContextReg(ctxt,REG_EBP) << endl;
	GetLock(&lock, threadid+1);
	ADDRINT esp=PIN_GetContextReg(ctxt,REG_ESP)|0xffff;
	StackBaseTable[threadid]=esp;
	*(proc+(offset++))='N';
	*(proc+(offset++))=' ';
	_itoa(threadid,(char*)proc+offset,10);
	offset+=(threadid<10?2:(threadid<100?3:4));
	*(proc+offset-1)=' ';
	_itoa(esp,(char*)proc+offset,16);
	offset+=(esp>=0x10000000?9:(esp>=0x1000000?8:(esp>=0x100000?7:(esp>=0x10000?6:5))));
	*(proc+offset-1)='\n';
	ReleaseLock(&lock);
}

// This routine is executed every time a thread is destroyed.
VOID ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v)
{
//	fOutput1 << "Thread " << threadid << "Finished." <<endl;
}

int main (int argc, char *argv[])
{
	// Initialize pin
	if ( PIN_Init (argc, argv) )
	{
		return Usage();
	}

	InitLock (&lock);
	
	string OutputPath(KnobOutputPath.Value());
	if (OutputPath.back()!='\\')
		OutputPath.push_back('\\');
	fOutput1.open (OutputPath + "IMAGE_list.txt");
//	fOutput2.open ("Process.txt");
	if (fOutput1 == NULL /*|| fOutput2 == NULL*/)
	{
		printf ("File cannot be openned!\n");
		return -1;
	}
	hFile = WINDOWS::CreateFile((OutputPath + "Process.txt").c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	unsigned __int64 FileMappingSz = ((unsigned __int64)(KnobMaxLogSize.Value()))*0x40000000;
	hFileMapping = WINDOWS::CreateFileMapping(hFile,NULL,PAGE_READWRITE,(UINT32)(FileMappingSz>>32),(UINT32)(FileMappingSz&0xffffffff),NULL);
	if (hFileMapping == NULL)
	{
		fOutput1 << "FileMapping Failed!";
		fOutput1.close();
		exit(0);
	}
	proc = (WINDOWS::LPBYTE)WINDOWS::MapViewOfFile(hFileMapping, FILE_MAP_WRITE,0,0,BLOCK_SZ);
	if (proc == NULL)
	{
		fOutput1 << "FileMapping Failed 2!";
		fOutput1.close();
		exit(0);
	}

	hFile_list = WINDOWS::CreateFile((OutputPath + "BBL_list.txt").c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	hFileMapping_list = WINDOWS::CreateFileMapping(hFile_list,NULL,PAGE_READWRITE,0,0x10000000,NULL);
	if (hFileMapping_list == NULL)
	{
		fOutput1 << "FileMapping Failed!";
		fOutput1.close();
		exit(0);
	}
	bbllist = (WINDOWS::LPBYTE)WINDOWS::MapViewOfFile(hFileMapping_list, FILE_MAP_WRITE,0,0,0x10000000);
	if (bbllist == NULL)
	{
		fOutput1 << "FileMapping Failed 2!";
		fOutput1.close();
		exit(0);
	}

	String2WString (KnobTraceFile.Value(), wstrTraceFileName);
	WINDOWS::OSVERSIONINFO osinfo;
	osinfo.dwOSVersionInfoSize = sizeof (WINDOWS::OSVERSIONINFO);
	if (!GetVersionEx (&osinfo) )
		return 1;
	if (osinfo.dwMajorVersion == 6 && osinfo.dwMinorVersion == 1)
	{
		num_create = 0x42;
		num_open = 0xb3;
		num_read = 0x111;
		num_close = 0x32;
		num_move = 0x149;
		num_createsection = 0x54;
		num_mapviewofsection = 0xa8;
		num_unmapviewofsection = 0x181;
	}
	else if (osinfo.dwMajorVersion == 6 && osinfo.dwMinorVersion == 0)
	{
		num_create = 0x3c;
		num_open = 0xba;
		num_read = 0x102;
		num_close = 0x30;
		num_move = 0x12d;
		num_createsection = 0x4b;
		num_mapviewofsection = 0xb1;
		num_unmapviewofsection = 0x15c;
	}
	else if (osinfo.dwMajorVersion == 5 && osinfo.dwMinorVersion == 1)
	{
		num_create = 0x25;
		num_open = 0x74;
		num_read = 0xb7;
		num_close = 0x19;
		num_move = 0xe0;
		num_createsection = 0x32;
		num_mapviewofsection = 0x6c;
		num_unmapviewofsection = 0x10b;
	}
	else
	{
		return 1;
	}

	CountBBL = 0;
//	memset(EspEbpTable[0],0,100);
//	memset(EspEbpTable[1],0,100);

	// Register Analysis routines to be called when a thread begins/ends
	PIN_AddThreadStartFunction(ThreadStart, 0);
//	PIN_AddThreadFiniFunction(ThreadFini, 0);

//	INS_AddInstrumentFunction (Instrumentation, 0);
	PIN_AddSyscallEntryFunction (SyscallEntry, 0);
	PIN_AddSyscallExitFunction (SyscallExit, 0);
	PIN_InitSymbols();
	IMG_AddInstrumentFunction (ImageLoad, 0);
	TRACE_AddInstrumentFunction (Trace, 0);
	PIN_AddFiniFunction (Fini, 0);

	CODECACHE_ChangeCacheLimit(512*1024*1024);

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}
