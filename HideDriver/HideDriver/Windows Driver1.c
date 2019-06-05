/*
时间：2018年10月10日 09:48:59
作者：https://github.com/Sqdwr
学（抄）习（袭）自：https://github.com/ZhuHuiBeiShaDiao
*/
#include <ntddk.h>
#include "GET_MIPROCESSLOADERENTRY.h"
#include "SYSTEM_MODULE_STRUCT.h"

BOOLEAN GetDriverObjectByName(PDRIVER_OBJECT *DriverObject, WCHAR *DriverName)
{
	PDRIVER_OBJECT TempObject = NULL;
	UNICODE_STRING u_DriverName = { 0 };
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	RtlInitUnicodeString(&u_DriverName, DriverName);
	Status = ObReferenceObjectByName(&u_DriverName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, &TempObject);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("获取驱动对象%ws失败!错误码是：%x!\n", Status));
		*DriverObject = NULL;
		return FALSE;
	}

	*DriverObject = TempObject;
	return TRUE;
}

BOOLEAN SupportSEH(PDRIVER_OBJECT DriverObject)
{
	//因为驱动从链表上摘除之后就不再支持SEH了
	//驱动的SEH分发是根据从链表上获取驱动地址，判断异常的地址是否在该驱动中
	//因为链表上没了，就会出问题
	//学习（抄袭）到的方法是用别人的驱动对象改他链表上的地址

	PDRIVER_OBJECT BeepDriverObject = NULL;;
	PLDR_DATA_TABLE_ENTRY LdrEntry = NULL;

	GetDriverObjectByName(&BeepDriverObject, L"\\Driver\\beep");
	if (BeepDriverObject == NULL)
		return FALSE;

	//MiProcessLoaderEntry这个函数内部会根据Ldr中的DllBase然后去RtlxRemoveInvertedFunctionTable表中找到对应的项
	//之后再移除他，根据测试来讲..这个表中没有的DllBase就没法接收SEH，具体原理还没懂...
	//所以这里用系统的Driver\\beep用来替死...
	LdrEntry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	LdrEntry->DllBase = BeepDriverObject->DriverStart;
	ObDereferenceObject(BeepDriverObject);
	return TRUE;
}

VOID InitInLoadOrderLinks(PLDR_DATA_TABLE_ENTRY LdrEntry)
{
	InitializeListHead(&LdrEntry->InLoadOrderLinks);
	InitializeListHead(&LdrEntry->InMemoryOrderLinks);
}

VOID Reinitialize(PDRIVER_OBJECT DriverObject, PVOID Context, ULONG Count)
{
	MiProcessLoaderEntry m_MiProcessLoaderEntry = NULL;
	BOOLEAN bFlag = FALSE;
	ULONG *p = NULL;

	m_MiProcessLoaderEntry = Get_MiProcessLoaderEntry();
	if (m_MiProcessLoaderEntry == NULL)
		return;

	// bFlag = SupportSEH(DriverObject);

	m_MiProcessLoaderEntry(DriverObject->DriverSection, 0);
	InitInLoadOrderLinks((PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection);

	DriverObject->DriverSection = NULL;
	DriverObject->DriverStart = NULL;
	DriverObject->DriverSize = NULL;
	DriverObject->DriverUnload = NULL;
	DriverObject->DriverInit = NULL;
	DriverObject->DeviceObject = NULL;

	/*if (bFlag)
	{
		__try {
			*p = 0x100;
		}
		__except (1)
		{
			KdPrint(("SEH正确处理！\n"));
		}
	}*/
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	KdPrint(("Unload Success!\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegString)
{
	KdPrint(("Entry Driver!\n"));
	IoRegisterDriverReinitialization(DriverObject, Reinitialize, NULL);
	DriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}
