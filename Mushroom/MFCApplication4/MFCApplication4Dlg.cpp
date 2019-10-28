
/* 

	Mushroom.cpp : Made By 창준 2016 04 02

*/

#pragma comment(lib,"ws2_32.lib")
//#pragma comment (lib, "wpcap.lib")  winpcap 쓸떄 사용
#include "stdafx.h"
#include "MFCApplication4.h"
#include "MFCApplication4Dlg.h"
#include "afxdialogex.h"
#include "resource.h"
#include <stdio.h>
#include <windows.h>
#include <iostream>
#include <time.h>
#include <io.h>   
#include <fcntl.h>
#include <string>
#include <string.h>
#include <winsock2.h>
#include "pcap.h"
#include "NewDlg.h"


#define DESIRED_WINSOCK_VERSION    0x0101
#define MINIMUM_WINSOCK_VERSION    0x0001


#ifdef _DEBUG
#define new DEBUG_NEW
#endif
using namespace std;
#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1) 
#define PROTO_TCP	6



#define BUFSIZE 512
SOCKET sock; // 소켓
SYSTEMTIME st; //시간
COLORREF color_front;
COLORREF color_back = 0xBB66EE;

int delay = 50;

DWORD ThreadID;
HWND hWnd;
HWND hMP = FindWindow(NULL, "MapleStory");
HWND hKey = FindWindow(NULL, "VirtualKeyboard");
HWND m_hWnd = FindWindow(NULL, "Mushroom");
BOOL WARISTART = FALSE, ColorCheck = FALSE;


char SignalDevice[256], errbuf[PCAP_ERRBUF_SIZE];
pcap_if_t *alldevs;
pcap_if_t *d;
pcap_t *adhandle;

unsigned int	m_SOCK;
int				m_BUFFSZ;
unsigned char*	m_BUFF;		// 패킷 버퍼
int				m_PACKETSZ; // 버퍼에 읽은 패킷 크기	
unsigned char*	m_PDATA;	// 데이터 영역
unsigned char*	m_PDATATXT;	// 데이터 영역(Text)
int				m_DATASZ;	// 데이터 크기	
unsigned short	m_PROTO;	// 프로토콜
unsigned int	m_SRCIP;	// 송신 ip
unsigned int	m_DSTIP;	// 수신 ip
int				m_SRCPORT;	// 송신 port
int				m_DSTPORT;	// 수신 port
struct iphdr*	m_PIPH;		// IP 헤더
struct tcphdr*	m_PTCPH;	// TCP 헤더
struct udphdr*	m_PUDPH;	// UDP 헤더
struct icmphdr*	m_PICMPH;	// ICMP 헤더
unsigned char*	m_TXTBUFF;	// 출력용 버퍼
int				m_TXTSZ;

#ifdef _DEBUG
#define new DEBUG_NEW
#endif
struct iphdr {
	unsigned char ihl : 4,
		version : 4;
	unsigned char tos;
	unsigned short tot_len;
	unsigned short id;
	unsigned short frag_off;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short check;
	unsigned int saddr;
	unsigned int daddr;
};

struct tcphdr {
	unsigned short source;
	unsigned short dest;
	unsigned int seq;
	unsigned int ack_seq;

	unsigned short nsf : 1,
		res1 : 3,
		doff : 4,
		fin : 1,
		syn : 1,
		rst : 1,
		psh : 1,
		ack : 1,
		urg : 1,
		ece : 1,
		cwr : 1;

	unsigned short window;
	unsigned short check;
	unsigned short urg_ptr;
};

struct udphdr {
	unsigned short source;
	unsigned short dest;
	unsigned short len;
	unsigned short check;
};

struct icmphdr {
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	union {
		struct {
			unsigned short id;
			unsigned short sequence;
		} echo;
		unsigned int gateway;
		struct {
			unsigned short __unused;
			unsigned short mtu;
		} frag;
	} un;
};

int WARICOUNT; //와리카운터
int WARIDELAY; //와리딜레이
bool dir = 0;
bool cheak = FALSE;
int ix = 0;
int iy = 0;

int pos_x = 0; // 검은줄 기준점
int pos_y = 0;

int posuser_x = 0;
int posuser_y = 0;// 사용자 지정

int startstop = 0;
int thread_stop = 1;
bool expert_state = 0, PixelCheck = 0;//신호 인식 동작 여부
int numberopen = 50;    //창닫힘 횟수
bool isok_state = 0; //상점열기 스레드 동작 여부


int ishillstate; //언덕 여부
bool speed_state = 1; //차이나 광클 여부
bool login;  //로그인 스테이트
bool usercom;//유저 컴퓨터 인증
bool team_state = 0; //팀 광클 스레드

int protect_state = 0;
int login_state = 0;

static char str_num[50];  //시작 종료 인포
static char str_ing[50];
static char str_start[50];
static char str_end[50];
char Buffer[256]; //로그기록
int H[20] = { 0, }; //초기화

CString xy; //xy좌표
CString S_log; //로그
CString strIPAddress;
POINT warick1, warick2, StorePoint; //와리
COLORREF color, StoreColor;// 상점색

/*마우스 좌표상 픽셀값 따오기*/
int getpixcel(HDC hdc, int x, int y) {
	DWORD color;
	void *p = (void*)GetPixel;

	__asm {
		mov esi, esp;
		push dword ptr y;
		push dword ptr x;
		push hdc;
		mov eax, dword ptr[p];
		add eax, 5;

		call cmd;
	cmd:
		pop ecx;
		add ecx, 12;
		push ecx;

		mov edi, edi;
		push ebp;
		mov ebp, esp;

		jmp eax;

		mov color, eax;
	}

	return color;
}
/*사용자 정의 함수*/
DWORD WINAPI  SockStart(LPVOID Param); //일상대기
DWORD WINAPI SockStart2(LPVOID Param);// 고상대기
DWORD WINAPI WinPcapStart(LPVOID Param); //윈프캡모드
DWORD WINAPI PICXEL(LPVOID Param);//색
void CALLBACK WARITimerProc(HWND hWnd, UINT uMsg, UINT idEvent, DWORD dwTime);
void CALLBACK MTUTimerProc(HWND hWnd, UINT uMsg, UINT idEvent, DWORD dwTime);
void storename(); //일상대기
void storename2();// 고상대기
void storename3(); //말하면서대기
void OffWindowLine(); // 창크기조절v
void getitem(); // 아이템올리기
bool Isok(); // 4점인식
void ReSetMaket(); //일상재대기
void ReSetMaket2(); //고상재대기
void ReSetMaket3(); //고상재대기
void fullmode(); //풀모드
void ReSetStore(); //고상리상;
void LOGWRITE(char* log2); //로그
void TIMELOGWRITE(char* log2); //타임로그
void Click(int Count, int x, int y);// 와리
void SetClipboardText(CString strSource);//복사함수
void GetPixelMP(int x, int y, HWND hMP); //상점색
void ran();//랜작

// 응용 프로그램 정보에 사용되는 CAboutDlg 대화 상자입니다.

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

	// 대화 상자 데이터입니다.
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 지원입니다.

// 구현입니다.
protected:
	DECLARE_MESSAGE_MAP()
public:

	afx_msg void OnRun();

};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)


END_MESSAGE_MAP()

// CMFCApplication4Dlg 대화 상자

CMFCApplication4Dlg::CMFCApplication4Dlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_MFCAPPLICATION4_DIALOG, pParent)
	, start1(FALSE)
	, start2(FALSE)
	, how1(_T("일반상점"))
	, Name(_T("^^"))
	, price(_T("9999999999"))
	, enterdll(FALSE)
	, log2(_T("v"))
	, hoykeyf5(false)
	, mtu56(_T("56"))
	, MTU1476(_T("1476"))
	, LAN(FALSE)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMFCApplication4Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, log);
	DDX_CBString(pDX, IDC_COMBO1, how1);
	DDX_Text(pDX, IDC_EDIT1, Name);
	DDX_Text(pDX, IDC_EDIT3, price);
	DDX_Check(pDX, IDC_CHECK1, enterdll);
	DDX_Check(pDX, IDC_CHECK3, goout);
	DDX_LBString(pDX, IDC_LIST1, log2);
	DDX_Text(pDX, IDC_EDIT2, mtu56);
	DDX_Text(pDX, IDC_EDIT4, MTU1476);

	DDX_Control(pDX, IDC_EDIT5, WARI1);
	DDX_Control(pDX, IDC_EDIT6, WARI2);
	DDX_Control(pDX, IDC_LIST6, getIP);
	DDX_Check(pDX, IDC_CHECK4, LAN);
}

BEGIN_MESSAGE_MAP(CMFCApplication4Dlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CMFCApplication4Dlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CMFCApplication4Dlg::OnBnClickedButton2)
	ON_EN_CHANGE(IDC_EDIT1, &CMFCApplication4Dlg::OnEnChangeEdit1)
	ON_EN_CHANGE(IDC_EDIT3, &CMFCApplication4Dlg::OnEnChangeEdit3)
	ON_BN_CLICKED(IDC_CHECK1, &CMFCApplication4Dlg::OnBnClickedCheck1)
	ON_BN_CLICKED(IDC_CHECK3, &CMFCApplication4Dlg::OnBnClickedCheck3)
	ON_LBN_SELCHANGE(IDC_LIST1, &CMFCApplication4Dlg::OnLbnSelchangeList1)
	ON_COMMAND(IDR_HotKey, &CMFCApplication4Dlg::OnHotkey)
	ON_WM_KEYDOWN()
	ON_BN_CLICKED(IDC_BUTTON3, &CMFCApplication4Dlg::OnBnClickedButton3)


	ON_COMMAND(ID_HOTKET2, &CMFCApplication4Dlg::OnHotket2)

	ON_COMMAND(ID_WARI, &CMFCApplication4Dlg::OnWari)
	ON_COMMAND(ID_RUNMP, &CMFCApplication4Dlg::OnRunmp)
	ON_MESSAGE(WM_HOTKEY, OnHotKey)


	ON_BN_CLICKED(IDC_CHECK4, &CMFCApplication4Dlg::OnBnClickedCheck4)
END_MESSAGE_MAP()


// CMFCApplication4Dlg 메시지 처리기


/* 마우스 좌표 받아오기 */
void CMFCApplication4Dlg::OnMouseMove(UINT nFlags, CPoint point) {

	m_pos = point;

	Invalidate();
	CDialogEx::OnMouseMove(nFlags, point);

}
/* 설정한 핫키들*/
BOOL CMFCApplication4Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();


	if (hMP == FALSE) {
		MessageBox(_T("메이플을 실행시켜주세요."), _T("Error"),
			MB_ICONERROR | MB_OK);
	}
	CString Temp;
	Temp.Format("%s", GetLocalIP());
	getIP.AddString(Temp);

	ModifyStyle(WS_THICKFRAME, 0, SWP_FRAMECHANGED);

	//LOGWRITE("-------  Made By 창준  -------");
	// 시스템 메뉴에 "정보..." 메뉴 항목을 추가합니다.

	// IDM_ABOUTBOX는 시스템 명령 범위에 있어야 합니다.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 이 대화 상자의 아이콘을 설정합니다.  응용 프로그램의 주 창이 대화 상자가 아닐 경우에는
	//  프레임워크가 이 작업을 자동으로 수행합니다.
	SetIcon(m_hIcon, TRUE);			// 큰 아이콘을 설정합니다.
	SetIcon(m_hIcon, FALSE);		// 작은 아이콘을 설정합니다.

	// TODO: 여기에 추가 초기화 작업을 추가합니다.
	m_hAccelTable = ::LoadAccelerators(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDR_ACCELERATOR1));
	m_hAccelTable = ::LoadAccelerators(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDR_ACCELERATOR2));

	RegisterHotKey(m_hWnd, 3, MOD_NOREPEAT, VK_F3);
	RegisterHotKey(m_hWnd, 4, MOD_NOREPEAT, VK_F4);
	RegisterHotKey(m_hWnd, 6, MOD_NOREPEAT, VK_F6);
	RegisterHotKey(m_hWnd, 10, MOD_NOREPEAT, VK_F10);
	RegisterHotKey(m_hWnd, 11, MOD_NOREPEAT, VK_F11);
	//핫키설정

	return TRUE;  // 포커스를 컨트롤에 설정하지 않으면 TRUE를 반환합니다.
}

LONG CMFCApplication4Dlg::OnHotKey(WPARAM wParam, LPARAM IParam) {
	if (wParam == 4) {
		CString str;
		GetDlgItemText(IDC_EDIT1, str);
		SetClipboardText(str);
		ReSetStore();
	}
	if (wParam == 3) {

		GetCursorPos(&StorePoint);
		GetPixelMP(StorePoint.x, StorePoint.y, hMP);
		StoreColor = color;
		sprintf(Buffer, "픽셀값 X:%d Y: %d C: 0x%X", StorePoint.x, StorePoint.y, StoreColor);
		TIMELOGWRITE(": 픽셀 저장 완료");
		LOGWRITE(Buffer);

	}
	if (wParam == 6) {
		CString str;
		GetDlgItemText(IDC_EDIT1, str);
		SetClipboardText(str);
		ran();
		TIMELOGWRITE(": 랜작성공");
	}

	if (wParam == 10) {
		CString str;
		GetDlgItemText(IDC_EDIT1, str); //제목복사
		SetClipboardText(str);
		UpdateData(TRUE);
		if (hMP == FALSE) {
			MessageBox(_T("메이플을 실행시켜주세요."), _T("Error"),
				MB_ICONERROR | MB_OK);
		}

		else if (how1 == "일반상점") {

			TIMELOGWRITE(": 일상대기시작");
			OffWindowLine();
			storename();
			CreateThread(NULL, 0, SockStart, NULL, 0, &ThreadID);
			//CreateThread(NULL, 0, WinPcapStart, NULL, 0, &ThreadID);
			//CreateThread(NULL, 0, PICXEL, NULL, 0, &ThreadID);
		}

		else if (how1 == "고용상점") {
			TIMELOGWRITE(": 고상대기시작");
			OffWindowLine();
			CreateThread(NULL, 0, SockStart2, NULL, 0, &ThreadID);
			storename2();
		}

		else {
			MessageBox(_T("대기모드 선택."), _T("Error"),
				MB_ICONERROR | MB_OK);
		}

		UpdateData(TRUE);
		if (how1 == "일반상점" || how1 == "고용상점") {
			if (goout == TRUE) {
				OffWindowLine();
				WARIDELAY = (atoi(Buffer) * 60000);
				if (WARIDELAY == 0)
				{
					WARIDELAY = 1800000;
				}
				WARICOUNT = 0;

				SetTimer(1234, 1800000, (TIMERPROC)WARITimerProc); //와리 30분
				SetTimer(1235, 600000, (TIMERPROC)MTUTimerProc); //mtu 와리 20분
			}
		}
		if (enterdll == TRUE) {

			WinExec("netsh interface ipv4 set subinterface ""이더넷"" mtu=56 store=persisten", SW_HIDE);
		}
	}
	if (wParam == 11) {
		if (hMP == FALSE) {
			MessageBox(_T("메이플을 실행시켜주세요."), _T("Error"),
				MB_ICONERROR | MB_OK);
		}
		else {
			expert_state = FALSE;
			WARISTART = FALSE;
			KillTimer(1234);
			KillTimer(1235);
			TIMELOGWRITE(": 인식중지");
		}
	}

	return 0;
}



void CMFCApplication4Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 대화 상자에 최소화 단추를 추가할 경우 아이콘을 그리려면
//  아래 코드가 필요합니다.  문서/뷰 모델을 사용하는 MFC 응용 프로그램의 경우에는
//  프레임워크에서 이 작업을 자동으로 수행합니다.

void CMFCApplication4Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 그리기를 위한 디바이스 컨텍스트입니다.

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 클라이언트 사각형에서 아이콘을 가운데에 맞춥니다.
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 아이콘을 그립니다.
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}


}

// 사용자가 최소화된 창을 끄는 동안에 커서가 표시되도록 시스템에서
//  이 함수를 호출합니다.
HCURSOR CMFCApplication4Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


//핫키설정함수
BOOL CMFCApplication4Dlg::PreTranslateMessage(MSG* pMsg)
{
	// TODO: 여기에 특수화된 코드를 추가 및/또는 기본 클래스를 호출합니다.
	if (m_hAccelTable != NULL)
	{
		if (TranslateAccelerator(m_hWnd, m_hAccelTable, pMsg))
			return TRUE;
	}
	if (pMsg->message == WM_KEYDOWN)
	{
		if (pMsg->wParam == VK_RETURN || pMsg->wParam == VK_ESCAPE)
		{
			return TRUE;
		}
	}

	return CDialog::PreTranslateMessage(pMsg);

}

//복사함수
BOOL CopyToClipboard(CListCtrl* pListCtrl, LPCTSTR lpszSeparator = _T("\t"), BOOL bCopyHeaderText = FALSE)
{
	ASSERT(pListCtrl && ::IsWindow(pListCtrl->GetSafeHwnd()));

	CString sResult;
	POSITION pos = pListCtrl->GetFirstSelectedItemPosition();
	if (!pos)
		return TRUE;

	CWaitCursor wait;
	int nItem, nCount = 0;
	int nColumn = 1;

	if ((pListCtrl->GetStyle() & LVS_TYPEMASK) == LVS_REPORT &&
		pListCtrl->GetExtendedStyle() & LVS_EX_FULLROWSELECT)
	{
		CHeaderCtrl* pHeader = pListCtrl->GetHeaderCtrl();
		nColumn = pHeader ? pHeader->GetItemCount() : 1;

		if (bCopyHeaderText && pHeader)
		{
			for (int i = 0; i < nColumn; ++i)
			{
				TCHAR szBuffer[256];
				HDITEM hdi;
				hdi.mask = HDI_TEXT;
				hdi.pszText = szBuffer;
				hdi.cchTextMax = 256;

				pHeader->GetItem(i, &hdi);
				sResult += szBuffer;
				if (i != nColumn - 1)
					sResult += lpszSeparator;
			}
			++nCount;
		}
	}

	while (pos)
	{
		nItem = pListCtrl->GetNextSelectedItem(pos);
		if (0 != nCount)
			sResult += _T("\r\n");

		for (int i = 0; i < nColumn; ++i)
		{
			sResult += pListCtrl->GetItemText(nItem, i);
			if (i != nColumn - 1)
				sResult += lpszSeparator;
		}
		++nCount;
	}

	if (pListCtrl->OpenClipboard())
	{
		EmptyClipboard();

		int nLen = (sResult.GetLength() + 1) * sizeof(WCHAR);
		HGLOBAL hGlobal = GlobalAlloc(GMEM_MOVEABLE | GMEM_DDESHARE, nLen);
		LPBYTE pGlobalData = (LPBYTE)GlobalLock(hGlobal);

		USES_CONVERSION_EX;
		CopyMemory(pGlobalData, T2CW_EX(sResult, _ATL_SAFE_ALLOCA_DEF_THRESHOLD), nLen);
		SetClipboardData(CF_UNICODETEXT, hGlobal);

		GlobalUnlock(hGlobal);
		GlobalFree(hGlobal);

		CloseClipboard();
		return TRUE;
	}
	return FALSE;
}

/*소켓 셋팅 위해 현재 ip주소값 받아오기*/
CString CMFCApplication4Dlg::GetLocalIP(void)
{
	WSADATA wsaData;
	char name[255];
	CString ip; // ip 저장.
	PHOSTENT hostinfo;
	if (WSAStartup(MAKEWORD(2, 0), &wsaData) == 0)
	{
		if (gethostname(name, sizeof(name)) == 0)
		{
			if ((hostinfo = gethostbyname(name)) != NULL)
			{
				ip = inet_ntoa(*(struct in_addr *)*hostinfo->h_addr_list);
			}
		}
		WSACleanup();
	}
	return ip;
}


/* EDIT BOX 에 있는 TEXT값 복사해서 상점제목 가격 설정*/
int ClipBoard(char *source)
{
	int ok = OpenClipboard(NULL);
	if (!ok) return 0;
	HGLOBAL clipbuffer;
	char * buffer;
	EmptyClipboard();
	clipbuffer = GlobalAlloc(GMEM_DDESHARE, strlen(source) + 1);
	buffer = (char*)GlobalLock(clipbuffer);
	strcpy(buffer, source);
	GlobalUnlock(clipbuffer);
	SetClipboardData(CF_TEXT, clipbuffer);
	CloseClipboard();
	return 1;
}

//복사함수
void SetClipboardText(CString strSource)
{
	//put your text in source
	if (::OpenClipboard(NULL))
	{
		HGLOBAL clipbuffer;
		char * buffer;
		EmptyClipboard();
		clipbuffer = GlobalAlloc(GMEM_DDESHARE, strSource.GetLength() + 1);
		buffer = (char*)GlobalLock(clipbuffer);
		strcpy(buffer, LPCSTR(strSource));
		GlobalUnlock(clipbuffer);
		SetClipboardData(CF_TEXT, clipbuffer);
		CloseClipboard();
	}
}

/* 비활성 모드에서도 POST방식으로 메이플에 엔터값 전송*/
void PostMessageSend(HWND hMP, WPARAM wParam, LPARAM lParam)
{
	PostMessage(hMP, WM_KEYDOWN, wParam, lParam);
}


/* 더블클릭 */
void Click(int Count, int x, int y)
{
	SetCursorPos(x, y);
	for (int index = 0; index <= Count; index++)
	{
		mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
		mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
		mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
		mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
		mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
		mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	}
}


//로그
void LOGWRITE(char* log2)
{
	m_hWnd = FindWindow(NULL, "Mushroom");
	SendMessage(GetDlgItem(m_hWnd, IDC_LIST1), LB_ADDSTRING, NULL, (LPARAM)log2);
	SendMessage(GetDlgItem(m_hWnd, IDC_LIST1), LB_SETCURSEL, SendMessage(GetDlgItem(m_hWnd, IDC_LIST1), LB_GETCOUNT, 0, 0) - 1, 0);
}


//타임로그
void TIMELOGWRITE(char* log2)
{
	m_hWnd = FindWindow(NULL, "Mushroom");
	GetLocalTime(&st);
	sprintf(Buffer, "[%d:%d:%d] %s", st.wHour, st.wMinute, st.wSecond, log2);
	LOGWRITE(Buffer);
	SendMessage(GetDlgItem(m_hWnd, IDC_LIST1), LB_SETCURSEL, SendMessage(GetDlgItem(m_hWnd, IDC_LIST1), LB_GETCOUNT, 0, 0) - 1, 0);
}

void copy() {
	m_hWnd = FindWindow(NULL, "Mushroom");

	CString    csTemp;
	char*    pszTemp = new char[csTemp.GetLength() + 1];

	strcpy(pszTemp, csTemp);

	GetDlgItemText(m_hWnd, IDC_EDIT3, pszTemp, 1009);
	SetClipboardText(pszTemp);
	delete[] pszTemp;
}



void ran() {

	//WinExec("netsh interface ipv4 set subinterface ""이더넷"" mtu=20 store=persisten", SW_HIDE);
	WinExec("C:\\랜off", SW_HIDE);
	Sleep(1000);
	keybd_event(VK_ESCAPE, 0, 0, 0);
	keybd_event(VK_ESCAPE, 0, 2, 0);
	Sleep(50);
	storename();
	Sleep(50);
	keybd_event(VK_RETURN, 0, 0, 0);
	keybd_event(VK_RETURN, 0, 2, 0);
	Sleep(50);
	WinExec("C:\\랜on", SW_HIDE);
	getitem();
}


/*일반상점 대기용 상점제목 */
void storename() {
	//캐시창이동
	SetCursorPos(783, 64);
	//캐시탭 클릭
	Sleep(200);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0); // 마우스 왼쪽 버튼을 누릅니다.
	Sleep(200);
	//일상 이동
	SetCursorPos(663, 97);
	//일상더블클릭
	Sleep(200);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0); // 마우스 왼쪽 버튼을 누릅니다.
	Sleep(200);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	Sleep(200);

	//제목 v
	keybd_event(0xA2, 0, 0, 0);
	keybd_event(0x56, 0, 0, 0);
	Sleep(20);
	keybd_event(0x56, 0, 2, 0);
	keybd_event(0xA2, 0, 2, 0);
	Sleep(20);


}

/*고용상점 대기용 상점제목 입력 */
void storename2() {

	//캐시창이동
	SetCursorPos(787, 64);
	//캐시탭 클릭
	Sleep(200);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0); // 마우스 왼쪽 버튼을 누릅니다.
	Sleep(200);
	//고상 이동
	SetCursorPos(706, 95);
	//고상더블클릭
	Sleep(200);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0); // 마우스 왼쪽 버튼을 누릅니다.
	Sleep(200);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	Sleep(200);

	//제목 v
	keybd_event(0xA2, 0, 0, 0);
	keybd_event(0x56, 0, 0, 0);
	Sleep(20);
	keybd_event(0x56, 0, 2, 0);
	keybd_event(0xA2, 0, 2, 0);
	Sleep(20);
	keybd_event(VK_RETURN, 0, 0, 0);
	keybd_event(VK_RETURN, 0, 2, 0);
}

void storename3() {


	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0); // 마우스 왼쪽 버튼을 누릅니다.
	Sleep(100);
	//일상 이동
	SetCursorPos(663, 97);
	//일상더블클릭
	Sleep(100);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0); // 마우스 왼쪽 버튼을 누릅니다.
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	Sleep(100);

	//제목 v
	keybd_event(0xA2, 0, 0, 0);
	keybd_event(0x56, 0, 0, 0);
	Sleep(20);
	keybd_event(0x56, 0, 2, 0);
	keybd_event(0xA2, 0, 2, 0);
	Sleep(20);


}

/*메이플 창 활성화 시키기 */
void OffWindowLine()
{
	//S_CheckID();//보안모듈

	hMP = FindWindow(NULL, "MapleStory");
	Sleep(1);
	SetWindowPos(hMP, 0, 0, 0, 800, 600, SWP_NOSIZE);
	Sleep(1);
	SetWindowPos(hMP, 0, 0, 0, 800, 600, SWP_NOSIZE);
}


/* 상점 개설 확인 여부후 아이템 올리기*/
void getitem() {

	Sleep(delay);
	//장비창클릭
	SetCursorPos(666, 66);
	Sleep(50);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0); // 마우스 왼쪽 버튼을 누릅니다.
	Sleep(50);
	//장비템 클릭
	SetCursorPos(666, 105);
	Sleep(50);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	Sleep(50);
	//템올리는곳으로 이동
	SetCursorPos(187, 294);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	//99999억
	Sleep(100);


	copy();
	keybd_event(0xA2, 0, 0, 0);
	keybd_event(0x56, 0, 0, 0);
	Sleep(20);
	keybd_event(0x56, 0, 2, 0);
	keybd_event(0xA2, 0, 2, 0);

	Sleep(20);
	SetCursorPos(655, 68);

	Sleep(20);
	///엔터
	keybd_event(VK_RETURN, 0, 0, 0);
	keybd_event(VK_RETURN, 0, 2, 0);

	Sleep(50);
	//열기
	SetCursorPos(353, 145);
	Sleep(delay);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	Sleep(500);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	TIMELOGWRITE(": 상점개설성공");
}

/*일반상점 인식 재대기 하기 */
void ReSetMaket()
{
	//열기 실패창 닫기

	keybd_event(VK_RETURN, 0, 0, 0);
	keybd_event(VK_RETURN, 0, 2, 0);

	//캐시
	Sleep(30);
	SetCursorPos(784, 60);
	Sleep(30);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	Sleep(30);

	//캐시템 더블
	SetCursorPos(655, 102);
	Sleep(10);

	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	Sleep(10);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);

	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	Sleep(10);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);

	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	Sleep(10);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);

	Sleep(30);
	//제목 여기여기
	keybd_event(0xA2, 0, 0, 0);
	keybd_event(0x56, 0, 0, 0);
	Sleep(20);
	keybd_event(0x56, 0, 2, 0);
	keybd_event(0xA2, 0, 2, 0);
	Sleep(20);

	Sleep(200);
	TIMELOGWRITE("  :  일상재대기성공");
}


/* 고용상점 인식시 재대기 */
void ReSetMaket2() {


	//열기 실패창 닫기
	Sleep(300);
	keybd_event(VK_RETURN, 0, 0, 0);
	keybd_event(VK_RETURN, 0, 2, 0);

	//캐시
	Sleep(200);
	SetCursorPos(785, 61);
	Sleep(50);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	Sleep(50);

	//캐시템 더블
	SetCursorPos(692, 92);
	Sleep(100);

	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	Sleep(10);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);

	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	Sleep(10);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);

	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	Sleep(10);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);

	Sleep(500);
	keybd_event(0xA2, 0, 0, 0);
	keybd_event(0x56, 0, 0, 0);
	Sleep(20);
	keybd_event(0x56, 0, 2, 0);
	keybd_event(0xA2, 0, 2, 0);
	Sleep(20);

	Sleep(500);
	keybd_event(VK_RETURN, 0, 0, 0);
	keybd_event(VK_RETURN, 0, 2, 0);
	TIMELOGWRITE(": 고상재대기성공");

}

/* 리상 하는 함수*/
void ReSetStore() {

	OffWindowLine();
	SetForegroundWindow(hMP);
	//상점닫기
	SetCursorPos(344, 164);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	//정말끄시겟습니까?
	Sleep(100);
	keybd_event(VK_RETURN, 0, 0, 0);
	keybd_event(VK_RETURN, 0, 2, 0);
	keybd_event(VK_RETURN, 0, 0, 0);
	keybd_event(VK_RETURN, 0, 2, 0);
	//아이템과 메소 모두찾앗습니다
	Sleep(300);
	keybd_event(VK_RETURN, 0, 0, 0);
	keybd_event(VK_RETURN, 0, 2, 0);
	keybd_event(VK_RETURN, 0, 0, 0);
	keybd_event(VK_RETURN, 0, 2, 0);
	keybd_event(VK_RETURN, 0, 0, 0);
	keybd_event(VK_RETURN, 0, 2, 0);
	//아이템메소 찾는거 끄기


	//캐시창이동
	SetCursorPos(787, 64);
	//캐시탭 클릭
	Sleep(200);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0); // 마우스 왼쪽 버튼을 누릅니다.
	Sleep(200);
	//고상 이동
	SetCursorPos(706, 95);
	//고상더블클릭
	Sleep(200);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0); // 마우스 왼쪽 버튼을 누릅니다.
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	Sleep(200);

	//제목 edit값 복사
	keybd_event(0xA2, 0, 0, 0);
	keybd_event(0x56, 0, 0, 0);
	Sleep(20);
	keybd_event(0x56, 0, 2, 0);
	keybd_event(0xA2, 0, 2, 0);
	Sleep(20);
	keybd_event(VK_RETURN, 0, 0, 0);
	keybd_event(VK_RETURN, 0, 2, 0);
	keybd_event(VK_RETURN, 0, 0, 0);
	keybd_event(VK_RETURN, 0, 2, 0);
	keybd_event(VK_RETURN, 0, 0, 0);
	keybd_event(VK_RETURN, 0, 2, 0);

	Sleep(100);
	//장비창클릭
	SetCursorPos(666, 66);
	Sleep(50);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0); // 마우스 왼쪽 버튼을 누릅니다.
	Sleep(50);
	//장비템 클릭
	SetCursorPos(666, 105);
	Sleep(50);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	Sleep(50);
	//템올리는곳으로 이동
	SetCursorPos(187, 294);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	//99999억
	Sleep(50);

	copy();
	keybd_event(0xA2, 0, 0, 0);
	keybd_event(0x56, 0, 0, 0);
	Sleep(20);
	keybd_event(0x56, 0, 2, 0);
	keybd_event(0xA2, 0, 2, 0);
	SetCursorPos(655, 68);

	Sleep(20);
	///엔터
	keybd_event(VK_RETURN, 0, 0, 0);
	keybd_event(VK_RETURN, 0, 2, 0);

	Sleep(50);
	//열기
	SetCursorPos(353, 145);
	Sleep(300);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
	Sleep(200);
	TIMELOGWRITE("  :  리상완료");
}



void GetPixelMP(int x, int y, HWND hMP)
{
	HDC hdc = GetDC(hMP);
	color = GetPixel(hdc, x, y);
}

/*반응 했을시 상점을 잡았는지 체크*/
bool Isok()
{
	Sleep(500);
	TIMELOGWRITE(": 상점개설여부확인중");

	HDC hdc;
	COLORREF c_back1, c_back2, c_back3, c_back4;
	hdc = GetDC(NULL);
	CWindowDC dc(NULL);

	SetForegroundWindow(hWnd);
	Sleep(200);
	c_back1 = GetPixel(hdc, 500, 220);
	Sleep(1);
	c_back2 = GetPixel(hdc, 500, 250);
	Sleep(1);
	c_back3 = GetPixel(hdc, 500, 270);
	Sleep(1);
	c_back4 = GetPixel(hdc, 500, 300);

	SetForegroundWindow(hMP);
	if ((c_back1 == 16777215) && (c_back2 == 16777215) && (c_back3 == 16777215)) {//&& (c_back4 == 16777215)) {
		return 1;
	}// && (c_back3 == 16777215) && (c_back4 == 16777215)) return 1;

	return 0;


}

/*비활성 모드*/
void fullmode() {

	hMP = FindWindow(NULL, "MapleStory");
	//SetWindowPos(hMP, 0, 0, 0, 800, 600, SW_MAXIMIZE);
	Sleep(500);
	CloseWindow(hMP);
	SetWindowPos(hMP, 0, 0, 0, 800, 600, SW_SHOWNORMAL);

}

void ReSetMaket3() {

	Sleep(50);
	keybd_event(VK_RETURN, 0, 0, 0);
	keybd_event(VK_RETURN, 0, 2, 0);

}

/*일반 상점 대기 메인 스레드*/
DWORD WINAPI SockStart(LPVOID Param)
{

	m_hWnd = FindWindow(NULL, "Mushroom");


	char ac[255] = { 0, };
	unsigned long v = 1, v2;


	struct in_addr addr;

	expert_state = 1; // recvfrom 초기화
	PixelCheck = 0;
	//UpMapleWindow();

	SetForegroundWindow(hMP);

	//	Protect1();  ///////////////////------------------보안

	// 윈속 초기화
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
		return -1;
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);

	if (sock == INVALID_SOCKET) {
		MessageBox(NULL, "관리자권한으로 실행해주세요.", "ERROR", MB_OK);
		return 0;
	}

	if (gethostname(ac, sizeof(ac)) != SOCKET_ERROR)
	{
		struct hostent *phe = gethostbyname(ac);
		if (phe != NULL)
		{
			memcpy(&addr, phe->h_addr_list[0], sizeof(struct in_addr));
		}

	}

	struct sockaddr_in SockAddr;
	ZeroMemory(&SockAddr, sizeof(SockAddr));
	SockAddr.sin_family = AF_INET;
	SockAddr.sin_port = NULL;
	SockAddr.sin_addr.s_addr = addr.s_addr;
	if (bind(sock, (sockaddr *)&SockAddr, sizeof(SockAddr)) == SOCKET_ERROR)
	{
		MessageBox(NULL, "바인딩", "에러", MB_OK);
	}


	struct sockaddr_in fromAddr;
	int fromAddrLen = sizeof(fromAddr);


	if (WSAIoctl(sock, SIO_RCVALL, &v, sizeof(v), 0, 0, &v2, 0, 0) == SOCKET_ERROR)
	{
		MessageBox(NULL, "옵션 실패 ", "에러", MB_OK);
	}


	HDC hdc;
	hdc = GetDC(NULL);


	int iphsz, hsz, pksz;

	m_BUFFSZ = 65536 * 2;

	// 패킷 버퍼 생성
	m_BUFF = (unsigned char*)malloc(m_BUFFSZ + 2);
	//m_PDATATXT=(unsigned char*)malloc(m_BUFFSZ+2);
	m_PIPH = (struct iphdr*)m_BUFF;
	ColorCheck == TRUE;
	while (expert_state)
	{

		memset(&fromAddr, 0, fromAddrLen);
		//   m_PACKETSZ = recvfrom(sock,(char*)m_BUFF,m_BUFFSZ,0,(struct sockaddr *)&fromAddr,&fromAddrLen);
		m_PACKETSZ = recvfrom(sock, (char*)m_BUFF, m_BUFFSZ, 0, (struct sockaddr *)&fromAddr, &fromAddrLen);


		if (m_PACKETSZ > 0) {

			m_PROTO = m_PIPH->protocol;

			m_SRCPORT = 0;

			iphsz = (m_PIPH->ihl * 4);
			pksz = m_PACKETSZ;


			//if(m_PROTO==PROTO_TCP && m_SRCPORT == 80 ) {
			if (m_PROTO == PROTO_TCP) {

				m_PTCPH = (struct tcphdr*)&m_BUFF[iphsz];
				m_SRCPORT = ntohs(m_PTCPH->source);
				//			m_DSTPORT=ntohs(m_PTCPH->dest);			
				hsz = m_PTCPH->doff * 4;
				m_PDATA = (unsigned char*)&m_BUFF[iphsz + hsz];

				m_DATASZ = pksz - iphsz - hsz;


				if (m_SRCPORT >= 0x2124 && m_SRCPORT <= 0x231d) {

					if (m_DATASZ == 11) {

						PostMessageSend(hMP, 13, 1835009);
						TIMELOGWRITE(": 신호반응");

						if (Isok())
						{
							KillTimer(m_hWnd, 1234);
							KillTimer(m_hWnd, 1235);
							getitem();
							cheak = 0;
							closesocket(sock);
							WSACleanup();
							expert_state = 0;
							PixelCheck = 1;
							Sleep(500);
							TIMELOGWRITE(": 인식종료");
							WinExec("netsh interface ipv4 set subinterface ""이더넷"" mtu=1476 store=persisten", SW_HIDE);
							ColorCheck == FALSE;
							return 1;

						}

						////재대기 함수 호출
						else {

							ReSetMaket();
							TIMELOGWRITE(": 상점개설실패");
							TIMELOGWRITE(": 재대기함수호출");
						}

						//NumberOpen();
					}
				}

			}

		}
	}


}

/*고용상점 대기 메인 스레드 */
DWORD WINAPI SockStart2(LPVOID Param)
{

	m_hWnd = FindWindow(NULL, "Mushroom");
	char ac[255] = { 0, };
	unsigned long v = 1, v2;

	struct in_addr addr;

	expert_state = 1; // recvfrom 초기화

					  //UpMapleWindow();

	SetForegroundWindow(hMP);

	//	Protect1();  ///////////////////------------------보안

	// 윈속 초기화
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
		return -1;

	// socket()
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);

	if (sock == INVALID_SOCKET) {

		MessageBox(NULL, "관리자권한으로 실행해주세요.", "ERROR", MB_OK);

		return 0;
	}


	if (gethostname(ac, sizeof(ac)) != SOCKET_ERROR)
	{
		struct hostent *phe = gethostbyname(ac);
		if (phe != NULL)
		{
			memcpy(&addr, phe->h_addr_list[0], sizeof(struct in_addr));
		}

	}


	// connect()
	struct sockaddr_in SockAddr;
	ZeroMemory(&SockAddr, sizeof(SockAddr));
	SockAddr.sin_family = AF_INET;
	SockAddr.sin_port = NULL;
	SockAddr.sin_addr.s_addr = addr.s_addr;

	//	if(GetPort()) SockAddr.sin_port = GetPort();
	//	else SockAddr.sin_port = NULL;
	//	SockAddr.sin_addr.s_addr = inet_addr("114.205.138.138");

	if (bind(sock, (sockaddr *)&SockAddr, sizeof(SockAddr)) == SOCKET_ERROR)
	{
		MessageBox(NULL, "바인딩", "에러", MB_OK);
	}


	struct sockaddr_in fromAddr;
	int fromAddrLen = sizeof(fromAddr);


	if (WSAIoctl(sock, SIO_RCVALL, &v, sizeof(v), 0, 0, &v2, 0, 0) == SOCKET_ERROR)
	{
		MessageBox(NULL, "옵션 실패 ", "에러", MB_OK);
		//ErrMsg("WSAIoctl() 오류");
		//goto ERR;
	}


	HDC hdc;
	hdc = GetDC(NULL);


	int iphsz, hsz, pksz;

	m_BUFFSZ = 65536 * 2;

	// 패킷 버퍼 생성
	m_BUFF = (unsigned char*)malloc(m_BUFFSZ + 2);
	//m_PDATATXT=(unsigned char*)malloc(m_BUFFSZ+2);
	m_PIPH = (struct iphdr*)m_BUFF;


	while (expert_state)
	{

		memset(&fromAddr, 0, fromAddrLen);
		//    m_PACKETSZ = recvfrom(sock,(char*)m_BUFF,m_BUFFSZ,0,(struct sockaddr *)&fromAddr,&fromAddrLen);
		m_PACKETSZ = recvfrom(sock, (char*)m_BUFF, m_BUFFSZ, 0, (struct sockaddr *)&fromAddr, &fromAddrLen);


		if (m_PACKETSZ > 0) {

			m_PROTO = m_PIPH->protocol;

			m_SRCPORT = 0;

			iphsz = (m_PIPH->ihl * 4);
			pksz = m_PACKETSZ;



			//if(m_PROTO==PROTO_TCP && m_SRCPORT == 80 ) {
			if (m_PROTO == PROTO_TCP) {


				m_PTCPH = (struct tcphdr*)&m_BUFF[iphsz];
				m_SRCPORT = ntohs(m_PTCPH->source);
				//			m_DSTPORT=ntohs(m_PTCPH->dest);			
				hsz = m_PTCPH->doff * 4;
				m_PDATA = (unsigned char*)&m_BUFF[iphsz + hsz];
				m_DATASZ = pksz - iphsz - hsz;

				if (m_SRCPORT >= 0x2124 && m_SRCPORT <= 0x231d) {



					if (m_DATASZ == 11) {

						PostMessageSend(hMP, 13, 1835009);
						TIMELOGWRITE(": 신호반응");

						if (Isok())
						{

							KillTimer(m_hWnd, 1234);
							KillTimer(m_hWnd, 1235);
							getitem();
							closesocket(sock);
							WSACleanup();
							expert_state = 0;
							Sleep(500);
							TIMELOGWRITE(": 인식종료");
							WinExec("netsh interface ipv4 set subinterface ""이더넷"" mtu=1476 store=persisten", SW_HIDE);
							return 1;

						}


						////재대기 함수 호출
						else {

							ReSetMaket2();
							TIMELOGWRITE(": 상점개설실패");
							TIMELOGWRITE(": 재대기함수호출");
						}

						//NumberOpen();
					}

				}

			}

		}
	}
}

/* 신호 깨짐 방지 신호 + 색값 인식*/
DWORD WINAPI PICXEL(LPVOID Param) {

	expert_state = 1;
	SetForegroundWindow(hMP);
	if (color != StoreColor) {
		PostMessageSend(hMP, 13, 1835009);
		TIMELOGWRITE(": 색반응");
		if (Isok())
		{

			//	KillTimer(m_hWnd, 1234);
			//	KillTimer(m_hWnd, 1235);
			getitem();
			closesocket(sock);
			WSACleanup();
			expert_state = 0;
			Sleep(500);
			TIMELOGWRITE(": 인식종료");
			WinExec("netsh interface ipv4 set subinterface ""이더넷"" mtu=1476 store=persisten", SW_HIDE);
			return 1;

		}


		////재대기 함수 호출
		else {

			ReSetMaket2();
			TIMELOGWRITE(": 상점개설실패");
			TIMELOGWRITE(": 재대기함수호출");
		}

	}


}
/* WINPCAP 모드 실험중*/
/*
DWORD WINAPI WinPcapStart(LPVOID Param)
{


	char *filter = "tcp && src portrange 8585-8589";
	//SignalCount = 0;
	//sprintf(Buffer, "%d", SignalCount);
	//SetDlgItemText(MainDlg, COUNT_STATIC, Buffer);
	int res;
	int inum = atoi(SignalDevice);
	int i = 0;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	//필터룰 지정
	struct bpf_program fcode;
	bpf_u_int32 NetMask;
	//네트워크 다바이스 목록을 가져온다.
	// alldevs에 리스트 형태로 저장되며, 에러시 errbuf에 에러 내용 저장
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		sprintf(Buffer, "Error in pcap_findalldevs: %s", errbuf);
		//		MessageBox(MainDlg, Buffer, TEXT("ERROR"), 16);
		return -1;
	}
	//네트워크 다바이스명을 출력한다.
	for (d = alldevs; d; d = d->next)
	{
		++i;
	}
	//에러 처리
	if (i == 0)
	{
		//MessageBox(MainDlg, TEXT("No interfaces found! Make sure WinPcap is installed."), TEXT("ERROR"), 16);
		return -1;
	}

	//캡처할 네트워크 디바이스 선택
	// 입력값의 유효성 판단
	if (inum < 1 || inum > i)
	{
		//	MessageBox(MainDlg, TEXT("Interface number out of range."), TEXT("ERROR"), 16);
			// 장치 목록 해제
		pcap_freealldevs(alldevs);
		return -1;
	}

	 사용자가 선택한 장치목록 선택
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
	Open the device
	if ((adhandle = pcap_open(d->name,          // name of the device
		65536,            // portion of the packet to capture.
						  // 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode　  TopSeven　
		1,             // read timeout
		NULL,             // authentication on the remote machine
		errbuf            // error buffer
		)) == NULL)
	{
		sprintf(Buffer, "Unable to open the adapter. %s is not supported by WinPcap", d->name);
		//	MessageBox(MainDlg, TEXT(Buffer), TEXT("ERROR"), 16);
			//Free the device list
		pcap_freealldevs(alldevs);
		return -1;
	}
//	if (SendMessage(GetDlgItem(m_hWnd, IDC_CHECK4), BM_GETCHECK, 0, 0) != BST_UNCHECKED)

	// 넷마스크 지정, 이부분은 아직 잘 모르겠음
	NetMask = 0xffffff;

	// 사용자가 정의한 필터룰 컴파일
	if (pcap_compile(adhandle, &fcode, filter, 1, NetMask) < 0)
	{
	//	MessageBox(MainDlg, TEXT("Error compiling filter: wrong syntax."), TEXT("ERROR"), 16);
		pcap_close(adhandle);
		return -3;
	}

	// 사용자가 정의한 필터룰 적용
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		//MessageBox(MainDlg, TEXT("Error setting the filter"), TEXT("ERROR"), 16);
		pcap_close(adhandle);
		return -4;
	}
	else
	{
		LOGWRITE("신호MAX적용.");
	}



	At this point, we don't need any more the device list. Free it
	pcap_freealldevs(alldevs);
	HDC hdc;
	hdc = GetDC(NULL);

	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
	{
		if (header->caplen == 64)
		{
			PostMessageSend(hMP, 13, 1835009);
			TIMELOGWRITE("  :  신호반응");
			if (Isok())
			{
				getitem();
				cheak = 0;
				closesocket(sock);
				WSACleanup();
				expert_state = 0;
				KillTimer(m_hWnd, 1234);
				Sleep(500);
				TIMELOGWRITE("  :  인식종료");

				return 1;

			}
		}
	}
}
*/


/* 신호인식 시작버튼*/
void CMFCApplication4Dlg::OnBnClickedButton1()
{


	//ClipBoard("hi");
	CString str;
	GetDlgItemText(IDC_EDIT1, str); //제목복사
	SetClipboardText(str);
	UpdateData(TRUE);
	if (hMP == FALSE) {
		MessageBox(_T("메이플을 실행시켜주세요."), _T("Error"),
			MB_ICONERROR | MB_OK);
	}

	else if (how1 == "일반상점") {

		TIMELOGWRITE(": 일상대기시작");
		OffWindowLine();
		storename();
		CreateThread(NULL, 0, SockStart, NULL, 0, &ThreadID);
		//CreateThread(NULL, 0, WinPcapStart, NULL, 0, &ThreadID);
		//CreateThread(NULL, 0, PICXEL, NULL, 0, &ThreadID);
	}

	else if (how1 == "고용상점") {
		TIMELOGWRITE(": 고상대기시작");
		OffWindowLine();
		CreateThread(NULL, 0, SockStart2, NULL, 0, &ThreadID);
		storename2();
	}

	else {
		MessageBox(_T("대기모드 선택."), _T("Error"),
			MB_ICONERROR | MB_OK);
	}

	UpdateData(TRUE);
	if (how1 == "일반상점" || how1 == "고용상점") {
		if (goout == TRUE) {
			OffWindowLine();
			WARIDELAY = (atoi(Buffer) * 60000);
			if (WARIDELAY == 0)
			{
				WARIDELAY = 1800000;
			}
			WARICOUNT = 0;

			SetTimer(1234, 1800000, (TIMERPROC)WARITimerProc); //와리 30분
			SetTimer(1235, 600000, (TIMERPROC)MTUTimerProc); //mtu 와리 20분
		}
	}
	if (enterdll == TRUE) {

		WinExec("netsh interface ipv4 set subinterface ""이더넷"" mtu=56 store=persisten", SW_HIDE);
	}

}

/*종료 버튼*/
void CMFCApplication4Dlg::OnBnClickedButton2()
{
	::SendMessage(GetSafeHwnd(), WM_CLOSE, NULL, NULL);
}

/*중지 버튼*/
void CMFCApplication4Dlg::OnBnClickedButton3()
{
	if (hMP == FALSE) {
		MessageBox(_T("메이플을 실행시켜주세요."), _T("Error"),
			MB_ICONERROR | MB_OK);
	}
	else {
		expert_state = FALSE;
		WARISTART = FALSE;
		KillTimer(1234);
		KillTimer(1235);
		TIMELOGWRITE(": 인식중지");
	}
}

/*제목 && 가격 */
void CMFCApplication4Dlg::OnEnChangeEdit1() {}
void CMFCApplication4Dlg::OnEnChangeEdit3() {}

/*엔딜 제거 하기 (MTU값 조절 하기)*/
void CMFCApplication4Dlg::OnBnClickedCheck1()
{
	UpdateData(TRUE);
	if (enterdll == TRUE) {
		CString str;
		GetDlgItemText(IDC_EDIT2, str); //제목복사
		SetClipboardText(str);
		S_log.Format("MTU = %s 엔딜제거", str);
		log.AddString(S_log);
		//	WinExec("netsh interface ipv4 set subinterface ""Local Area Connection"" mtu=56 store=persisten", SW_HIDE);
		WinExec("netsh interface ipv4 set subinterface ""이더넷"" mtu=56 store=persisten", SW_HIDE);
		//	WinExec("netsh interface ipv4 set subinterface ""로컬 영역 연결"" mtu=56 store=persisten", SW_HIDE);
		//	WinExec("netsh interface ipv4 set subinterface ""무선 네트워크 연결"" mtu=56 store=persisten", SW_HIDE);
	}
	else if (enterdll == FALSE) {
		CString str;
		GetDlgItemText(IDC_EDIT4, str); //제목복사
		SetClipboardText(str);
		S_log.Format("MTU = %s 엔딜제거해제", str);
		log.AddString(S_log);

		//	WinExec("netsh interface ipv4 set subinterface ""Local Area Connection"" mtu=1476 store=persisten", SW_HIDE);
		WinExec("netsh interface ipv4 set subinterface ""이더넷"" mtu=1476 store=persisten", SW_HIDE);
		//	WinExec("netsh interface ipv4 set subinterface ""로컬 영역 연결"" mtu=1476 store=persisten", SW_HIDE);
		//	WinExec("netsh interface ipv4 set subinterface ""무선 네트워크 연결"" mtu=1476 store=persisten", SW_HIDE);
	}

}

//와리창 구현중
void CMFCApplication4Dlg::OnBnClickedCheck3()
{
	UpdateData(TRUE);
	if (goout == TRUE) {
		OffWindowLine();
		LOGWRITE("와리①② 설정핫키 == F1,F2");
	}
}
/* 렌작 하기*/
void CMFCApplication4Dlg::OnBnClickedCheck4()
{
	UpdateData(TRUE);
	if (LAN == TRUE) {
		NewDlg dlg;
		dlg.DoModal();
	}
}
/* F5 리상하기 */
void CMFCApplication4Dlg::OnHotkey()
{
	UpdateData(TRUE);
	//ClipBoard("chagnjun");
	CString str;
	GetDlgItemText(IDC_EDIT1, str); //copy
	SetClipboardText(str);

	if (hMP == FALSE) {
		MessageBox(_T("메이플을 실행시켜주세요."), _T("Error"),
			MB_ICONERROR | MB_OK);
	}
	else {
		ReSetStore();
	}
}


/*		F1와리		*/
void CMFCApplication4Dlg::OnHotket2()
{
	GetCursorPos(&warick1);
	warick1.x;
	warick1.y;
	xy.Format("x=%d,y=%d", warick1.x, warick1.y);
	WARI1.SetWindowText(xy);
	TIMELOGWRITE(": 와리①번 지정완료");
}

/*		F2와리		*/
void CMFCApplication4Dlg::OnWari()
{

	GetCursorPos(&warick2);
	warick2.x;
	warick2.y;
	xy.Format("x=%d,y=%d", warick2.x, warick2.y);
	WARI2.SetWindowText(xy);
	TIMELOGWRITE(": 와리②번 지정완료");
}

/* 메이플 실행*/
void CMFCApplication4Dlg::OnRunmp()
{
	//	ShellExecute(NULL, "open", "C:\Nexon\Maple\GameLauncher.exe", NULL, NULL, SW_SHOW);
}

/*와리 하는 함수*/
void CALLBACK WARITimerProc(HWND hWnd, UINT uMsg, UINT idEvent, DWORD dwTime)
{


	Sleep(2000);
	WARISTART = TRUE;
	TIMELOGWRITE(": 와리사용");
	TIMELOGWRITE(": 와리시작");
	Sleep(500);
	keybd_event(VK_ESCAPE, 0, 0, 0);
	keybd_event(VK_ESCAPE, 0, 2, 0);
	Sleep(500);

	switch (WARICOUNT)
	{
	case 0:
		TIMELOGWRITE(": 1번상점들어가기");
		Click(2, warick1.x, warick1.y);
		Sleep(500);
		//	if (StoreOpenCheck(hMP))
		{
			Sleep(300);
			TIMELOGWRITE(": 1번상점에서 나가기");
			keybd_event(VK_ESCAPE, 0, 0, 0);
			keybd_event(VK_ESCAPE, 0, 2, 0);
			WARICOUNT++;
		}
	case 1:
		TIMELOGWRITE(": 2번상점들어가기");
		Click(2, warick2.x, warick2.y);
		Sleep(500);
		//if (StoreOpenCheck(hMP))
		{
			Sleep(300);
			TIMELOGWRITE(": 2번상점에서 나가기");
			keybd_event(VK_ESCAPE, 0, 0, 0);
			keybd_event(VK_ESCAPE, 0, 2, 0);
			WARICOUNT++;
		}
		break;
	}
	if (WARICOUNT >= 1)
		WARICOUNT = 0;
	//if (StoreOpenCheck(hMP))
	//{
	//	Sleep(1000);
	//	PostMessageSend(hMP, 27, 65537);
	//	Sleep(300);
	//}
	TIMELOGWRITE(": 와리 종료");
	//	MapleIven(hMP);
	storename();
	storename();
	TIMELOGWRITE(": 재대기 시작");

	WARISTART = FALSE;

}

void CALLBACK MTUTimerProc(HWND hWnd, UINT uMsg, UINT idEvent, DWORD dwTime)
{
	WinExec("netsh interface ipv4 set subinterface ""이더넷"" mtu=1476 store=persisten", SW_HIDE);
	TIMELOGWRITE(": MTU → 1476");
	Sleep(5000);
	WinExec("netsh interface ipv4 set subinterface ""이더넷"" mtu=56 store=persisten", SW_HIDE);
	TIMELOGWRITE(": MTU → 56");
}




