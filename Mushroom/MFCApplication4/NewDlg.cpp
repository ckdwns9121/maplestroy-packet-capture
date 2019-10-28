

/*
	Mushroom.cpp : Made By 창준 2016 04 02
	MTU 값 컨트롤 랜작 다이얼로그
*/

#include "stdafx.h"
#include "NewDlg.h"
#include "afxdialogex.h"
#include "Resource.h"

// NewDlg 대화 상자입니다.

IMPLEMENT_DYNAMIC(NewDlg, CDialogEx)

NewDlg::NewDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DIALOG1, pParent)
{

}

NewDlg::~NewDlg()
{
}

void NewDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(NewDlg, CDialogEx)
	ON_BN_CLICKED(IDC_BUTTON2, &NewDlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON1, &NewDlg::OnBnClickedButton1)
END_MESSAGE_MAP()


// NewDlg 메시지 처리기입니다.


void NewDlg::OnBnClickedButton2()
{
	MessageBox(_T("랜켜짐"));
	WinExec("netsh interface ipv4 set subinterface ""이더넷"" mtu=1500 store=persisten", SW_HIDE);
//	WinExec("netsh interface ipv4 set subinterface ""로컬 영역 연결"" mtu=56 store=persisten", SW_HIDE);
//	WinExec("netsh interface ipv4 set subinterface ""Local Area Connection"" mtu=1476 store=persisten", SW_HIDE);
//	WinExec("netsh interface ipv4 set subinterface ""무선 네트워크 연결"" mtu=1476 store=persisten", SW_HIDE);
}


void NewDlg::OnBnClickedButton1()
{
	MessageBox(_T("랜꺼짐"));

	WinExec("netsh interface ipv4 set subinterface ""이더넷"" mtu=30 store=persisten", SW_HIDE);
//	WinExec("netsh interface ipv4 set subinterface ""로컬 영역 연결"" mtu=30 store=persisten", SW_HIDE);
//	WinExec("netsh interface ipv4 set subinterface ""Local Area Connection"" mtu=30 store=persisten", SW_HIDE);
//	WinExec("netsh interface ipv4 set subinterface ""무선 네트워크 연결"" mtu=1476 store=persisten", SW_HIDE);
}