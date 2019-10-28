
// MFCApplication4Dlg.h : 헤더 파일
//

#pragma once
#include "afxwin.h"
#include "afxcmn.h"

//CIP AddressCtrl E_IPv;

// CMFCApplication4Dlg 대화 상자
class CMFCApplication4Dlg : public CDialogEx
{
// 생성입니다.
public:
	CMFCApplication4Dlg(CWnd* pParent = NULL);	// 표준 생성자입니다.
	virtual BOOL PreTranslateMessage(MSG* pMsg); //엔터키 esc 후킹
	static CWinThread* m_pThreadSend; //쓰레드종료
	CPoint m_pos; //마우스좌표





// 대화 상자 데이터입니다.
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MFCAPPLICATION4_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 지원입니다.
	afx_msg LONG OnHotKey(WPARAM wParam, LPARAM IParam);

// 구현입니다.
protected:
	HICON m_hIcon;
	HACCEL m_hAccelTable; //핫키설정
	//HACCEL m_hAccelTable2;
	// 생성된 메시지 맵 함수
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	void OnMouseMove(UINT nFlags, CPoint point);;
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton2();
	BOOL start1;
	BOOL start2;
	CListBox log; //로그


	CString how1; //대기상태
	
	CString Name; //제목
	afx_msg void OnEnChangeEdit1();
	afx_msg void OnEnChangeEdit3();

	CString price;
	afx_msg void OnBnClickedCheck1();
	BOOL enterdll;

	afx_msg void OnBnClickedCheck3();
	BOOL goout; //d와리
	CString log2;
	afx_msg void OnLbnSelchangeList1();
	afx_msg void OnHotkey();
	bool hoykeyf5;
	afx_msg void OnBnClickedButton3();
	CString mtu56;
	CString MTU1476;


	afx_msg void OnHotket2();
	CEdit WARI1;
	CEdit WARI2;

	afx_msg void OnWari();
	afx_msg void OnRunmp();

	CString GetLocalIP(void);

	
	CListBox getIP;
	CComboBox storemode;

	afx_msg void OnBnClickedCheck4();
	BOOL LAN;
};
