
// pcapApplicationDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "pcapApplication.h"
#include "pcapApplicationDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CpcapApplicationDlg 对话框



CpcapApplicationDlg::CpcapApplicationDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CpcapApplicationDlg::IDD, pParent)
	, pcapFile(_T(""))
	, path(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CpcapApplicationDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT1, pcapFile);
	DDX_Text(pDX, IDC_EDIT2, path);
}

BEGIN_MESSAGE_MAP(CpcapApplicationDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CpcapApplicationDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CpcapApplicationDlg::OnBnClickedCancel)
	ON_EN_CHANGE(IDC_EDIT1, &CpcapApplicationDlg::OnEnChangeEdit1)
	ON_BN_CLICKED(IDC_BUTTON1, &CpcapApplicationDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CpcapApplicationDlg::OnBnClickedButton2)
	ON_EN_CHANGE(IDC_EDIT2, &CpcapApplicationDlg::OnEnChangeEdit2)
	ON_EN_CHANGE(IDC_EDIT3, &CpcapApplicationDlg::OnEnChangeEdit3)
	ON_BN_CLICKED(IDC_BUTTON3, &CpcapApplicationDlg::OnBnClickedButton3)
END_MESSAGE_MAP()


// CpcapApplicationDlg 消息处理程序

BOOL CpcapApplicationDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
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

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CpcapApplicationDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CpcapApplicationDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CpcapApplicationDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CpcapApplicationDlg::OnBnClickedOk()
{
	// TODO: 在此添加控件通知处理程序代码
	//CDialogEx::OnOK();

	GetDlgItem(IDC_EDIT1)->GetWindowText(pcapFile);
	GetDlgItem(IDC_EDIT2)->GetWindowText(path);

	//CString convert to string
	USES_CONVERSION;
	std::string pcapFileStr (W2A(pcapFile));
	std::string pathStr (W2A(path)); 

	
	if (pcap.start(pathStr, pcapFileStr) == 0)
	{
		MessageBox(_T("啦啦啦啦,Succeeded!"), _T("callBack")); 
		//GetDlgItem(IDC_EDIT3)->SetWindowTextW(L"Succeeded!");
	}
	else
	{
		MessageBox(_T("唉唉唉唉,Failed!"), _T("callBack")); 
		//GetDlgItem(IDC_EDIT3)->SetWindowTextW(L"Failed!");
	}
}


void CpcapApplicationDlg::OnBnClickedCancel()
{
	// TODO: 在此添加控件通知处理程序代码
	CDialogEx::OnCancel();
}


void CpcapApplicationDlg::OnEnChangeEdit1()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。


	// TODO:  在此添加控件通知处理程序代码
}


void CpcapApplicationDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码

    // 设置过滤器   
    TCHAR szFilter[] = _T("文本文件(*.pcap)|*.pcap|所有文件(*.*)|*.*||"); 

    // 构造打开文件对话框   
    CFileDialog fileDlg(TRUE, _T("pcap"), NULL, 0, szFilter, this);   
    CString strFilePath;   
  
    // 显示打开文件对话框   
    if (IDOK == fileDlg.DoModal())   
    {   
        // 如果点击了文件对话框上的“打开”按钮，则将选择的文件路径显示到编辑框里   
        strFilePath = fileDlg.GetPathName();   
        SetDlgItemText(IDC_EDIT1, strFilePath);   
    }
}


void CpcapApplicationDlg::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码

	WCHAR szPath[MAX_PATH];     //存放选择的目录路径 
    CString str;

    ZeroMemory(szPath, sizeof(szPath));   

    BROWSEINFO bi;   
    bi.hwndOwner = m_hWnd;   
    bi.pidlRoot = NULL;   
    bi.pszDisplayName = szPath;   
    bi.lpszTitle = L"请选择需要打包的目录：";   
    bi.ulFlags = 0;   
    bi.lpfn = NULL;   
    bi.lParam = 0;   
    bi.iImage = 0;   
    //弹出选择目录对话框
    LPITEMIDLIST lp = SHBrowseForFolder(&bi);   

    if(lp && SHGetPathFromIDList(lp, szPath))
	{
		GetDlgItem(IDC_EDIT2)->SetWindowText(szPath);
    }
}


void CpcapApplicationDlg::OnEnChangeEdit2()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。


	// TODO:  在此添加控件通知处理程序代码
}


void CpcapApplicationDlg::OnEnChangeEdit3()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。


	// TODO:  在此添加控件通知处理程序代码
}


void CpcapApplicationDlg::OnBnClickedButton3()
{
	// TODO: 在此添加控件通知处理程序代码
	//CDialogEx::OnOK();

	GetDlgItem(IDC_EDIT1)->GetWindowText(pcapFile);
	GetDlgItem(IDC_EDIT2)->GetWindowText(path);

	//CString convert to string
	USES_CONVERSION;
	std::string pcapFileStr (W2A(pcapFile));
	std::string pathStr (W2A(path)); 

	
	if (sip.start(pathStr, pcapFileStr) == 0)
	{
		MessageBox(_T("啦啦啦啦,Succeeded!"), _T("callBack")); 
		//GetDlgItem(IDC_EDIT3)->SetWindowTextW(L"Succeeded!");
	}
	else
	{
		MessageBox(_T("唉唉唉唉,Failed!"), _T("callBack")); 
		//GetDlgItem(IDC_EDIT3)->SetWindowTextW(L"Failed!");
	}
}
