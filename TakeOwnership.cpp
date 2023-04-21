#include <windows.h>
#include <stdio.h>
#include <accctrl.h>
#include <aclapi.h>

DWORD AddAceToObjectsSecurityDescriptor (
    LPTSTR pszObjName,          // name of object
    SE_OBJECT_TYPE ObjectType,  // type of object
    LPTSTR pszTrustee,          // trustee for new ACE
    TRUSTEE_FORM TrusteeForm,   // format of trustee structure
    DWORD dwAccessRights,       // access mask for new ACE
    ACCESS_MODE AccessMode,     // type of ACE
    DWORD dwInheritance         // inheritance flags for new ACE
) 
{
    DWORD dwRes = 0;
    PACL pOldDACL = NULL, pNewDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    EXPLICIT_ACCESS ea;

    if (NULL == pszObjName) 
        return ERROR_INVALID_PARAMETER;

    // Get a pointer to the existing DACL.

    dwRes = GetNamedSecurityInfo(pszObjName, ObjectType, 
          DACL_SECURITY_INFORMATION,
          NULL, NULL, &pOldDACL, NULL, &pSD);
    if (ERROR_SUCCESS != dwRes) {
        printf( "GetNamedSecurityInfo Error %u\n", dwRes );
        goto Cleanup; 
    }  

    // Initialize an EXPLICIT_ACCESS structure for the new ACE. 

    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = dwAccessRights;
    ea.grfAccessMode = AccessMode;
    ea.grfInheritance= dwInheritance;
    ea.Trustee.TrusteeForm = TrusteeForm;
    ea.Trustee.ptstrName = pszTrustee;

    // Create a new ACL that merges the new ACE
    // into the existing DACL.

    dwRes = SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL);
    if (ERROR_SUCCESS != dwRes)  {
        printf( "SetEntriesInAcl Error %u\n", dwRes );
        goto Cleanup; 
    }  

    // Attach the new ACL as the object's DACL.

    dwRes = SetNamedSecurityInfo(pszObjName, ObjectType, 
          DACL_SECURITY_INFORMATION,
          NULL, NULL, pNewDACL, NULL);
    if (ERROR_SUCCESS != dwRes)  {
        printf( "SetNamedSecurityInfo Error %u\n", dwRes );
        goto Cleanup; 
    }  

    Cleanup:

        if(pSD != NULL) 
            LocalFree((HLOCAL) pSD); 
        if(pNewDACL != NULL) 
            LocalFree((HLOCAL) pNewDACL); 

        return dwRes;
}
int main(){

    HANDLE currentProcess = {};
    currentProcess = GetCurrentProcess();
    HANDLE hToken;

    if (currentProcess == NULL) {
        printf("OpenProcess() error : % u\n", GetLastError());
    }
    printf("Process opened succeed!\n");
    if (!OpenProcessToken(currentProcess, 0x0020 | 0x0008, &hToken)) {
        printf("[-] OpenProcessToken() error : % u\n", GetLastError());
    }
    printf("Open process token succeed!\n");
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL,"SeTakeOwnershipPrivilege",&luid)) 
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }else{
        printf("Luid: %u\n",luid);
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = 0x00000002;


    if (!AdjustTokenPrivileges(hToken,FALSE,&tp,0,(PTOKEN_PRIVILEGES)NULL,(PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }else{
        printf("AdjustTokenPrivileges Added\n");
    }
    DWORD dwRes = AddAceToObjectsSecurityDescriptor("C:\\test.txt",SE_FILE_OBJECT,"CHANGE",TRUSTEE_IS_NAME,GENERIC_READ|GENERIC_WRITE,GRANT_ACCESS,0);//(TRUSTEE_IS_NAME) CHANGE USERNAME
    if (ERROR_SUCCESS != dwRes)  {
      printf("AddAceToObjectsSecurityDescriptor Error %u\n", dwRes );
      return 1; 
    }else{
        printf("File ACL Modified\n");
    }
}