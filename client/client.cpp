// VClientDlg.cpp : ʵ���ļ�

#include "stdafx.h"
#include "VClient.h"
#include "VClientDlg.h"
#include "afxdialogex.h"
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib,"wsock32.lib")
#pragma comment(lib, "Ws2_32.lib") 

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#define ICMP_ECHO 8
#define ICMP_ECHOREPLY 0
#define ICMP_MIN 8 // minimum 8 byte icmp packet (just header)
#define ICMP_DEST_IP "127.0.0.1"    //��������ip��ַ
#define ICMP_PASSWORD 1234

UINT Send(PVOID hWnd);

/* The IP header */
typedef struct iphdr
{
	unsigned int h_len : 4; //4λ�ײ�����
	unsigned int version : 4; //IP�汾�ţ�4��ʾIPV4
	unsigned char tos; //8λ��������TOS
	unsigned short total_len; //16λ�ܳ��ȣ��ֽڣ�
	unsigned short ident; //16λ��ʶ
	unsigned short frag_and_flags; //3λ��־λ
	unsigned char ttl; //8λ����ʱ�� TTL
	unsigned char proto; //8λЭ�� (TCP, UDP ������)
	unsigned short checksum; //16λIP�ײ�У���
	unsigned int sourceIP; //32λԴIP��ַ
	unsigned int destIP; //32λĿ��IP��ַ
}IpHeader;

typedef struct _ihdr
{
	BYTE i_type; //8λ����
	BYTE i_code; //8λ����
	USHORT i_cksum; //16λУ��� 
	USHORT i_id; //ʶ��ţ�һ���ý��̺���Ϊʶ��ţ�
	USHORT i_seq; //�������к� 
	ULONG timestamp; //ʱ���
}IcmpHeader;

#define STATUS_FAILED 0xFFFF
#define DEF_PACKET_SIZE 1200
#define MAX_PACKET 6500
#define xmalloc(s) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,(s))
#define xfree(p) HeapFree (GetProcessHeap(),0,(p))

WSADATA wsaData;
SOCKET sockRaw = (SOCKET)NULL;
struct sockaddr_in dest, from;
struct hostent * hp;
int bread, datasize, retval, bwrote;
int fromlen;
int timeout;
char *icmp_data;
char *recvbuf;
unsigned int addr;
USHORT seq_no;
static int nCount;
CString str,tmp1,FileName;
CFile rwFile, rFile;
char Buf[DEF_PACKET_SIZE];
CString SFileName,fFileName;

//����icmpУ���
USHORT checksum(USHORT *buffer, int size)
{
	unsigned long cksum = 0;
	while (size >1)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size)
		cksum += *(UCHAR*)buffer;
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (USHORT)(~cksum);
}

void fill_icmp_data(char * icmp_data, int k)
{
	int i;
	char SendMsg[20] = "Hello World!";
	
	IcmpHeader *icmp_hdr;
	char *datapart;
	icmp_hdr = (IcmpHeader*)icmp_data;
	icmp_hdr->i_type = ICMP_ECHOREPLY;
	icmp_hdr->i_code = 0;
	icmp_hdr->i_id = (USHORT)GetCurrentProcessId();
	icmp_hdr->i_cksum = 0;
	icmp_hdr->i_seq = 0;
	datapart = icmp_data + sizeof(IcmpHeader);

	if (k == 0)
	{
		for (i = 0; i<sizeof(SendMsg); i++)
		{
			datapart[i] = SendMsg[i];
		}
	}
	if ((k == 5) || (k == 4))
		strncpy(datapart, tmp1, tmp1.GetLength());
	if (k == 6)
		memcpy(datapart, Buf, DEF_PACKET_SIZE);
	if (k == 7)
		memcpy(datapart, tmp1, tmp1.GetLength());
}

int c = 0;
//�Ա��Ľ��д���
void decode_resp(char *buf, int bytes, struct sockaddr_in *from)
{
	CVClientApp* pApp = (CVClientApp*)AfxGetApp();
	CVClientDlg* pDlg = (CVClientDlg*)pApp->m_pMainWnd;
	
	int i;
	IpHeader *iphdr;
	char *data, *instead;
	IcmpHeader *icmphdr;
	unsigned short iphdrlen;
	iphdr = (IpHeader *)buf;
	iphdrlen = iphdr->h_len * 4;
	icmphdr = (IcmpHeader*)(buf + iphdrlen);
	data = buf + iphdrlen + 12;
	CString str;

	if (icmphdr->i_seq == ICMP_PASSWORD)   //������ȷ��������ݶ�
	{
		if (icmphdr->i_code == 9)
		{
			while (strlen(data))
			{
				str.Format("%s", data);
				pDlg->m_clist.InsertString(-1, str);
				data = data + strlen(data) + 1;
			}
			c = 1;
		}
		if (icmphdr->i_code == 10)
			rFile.Write(data, DEF_PACKET_SIZE);
		if (icmphdr->i_code == 11)
		{
			rFile.Close();
			c = 1;
		}
		str.Format("%d bytes from %s: IcmpType %d IcmpCode %d", bytes, inet_ntoa(from->sin_addr), icmphdr->i_type, icmphdr->i_code);
		pDlg->m_show.InsertString(-1, str);
	}
	else
	{
		str = "Other ICMP Packets!\n";
		pDlg->m_show.InsertString(-1, str);
	}
}
// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
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


// CVClientDlg �Ի���

CVClientDlg::CVClientDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_VCLIENT_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CVClientDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_show);
	DDX_Control(pDX, IDC_LIST2, m_clist);
	DDX_Control(pDX, IDC_COMBO1, m_select);
}

BEGIN_MESSAGE_MAP(CVClientDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CVClientDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CVClientDlg::OnBnClickedCancel)
	ON_BN_CLICKED(IDC_BUTTON1, &CVClientDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CVClientDlg::OnBnClickedButton2)
END_MESSAGE_MAP()


// CVClientDlg ��Ϣ��������

BOOL CVClientDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵������ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
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

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ����Ӷ���ĳ�ʼ������
	fromlen = sizeof(from);
	timeout = 1000;
	addr = 0;
	seq_no = 0;
	nCount = 0;
	//WSA����
	if ((retval = WSAStartup(MAKEWORD(2, 1), &wsaData)) != 0)
	{
		str.Format("WSAStartup failed: %d\n", retval);
		AfxMessageBox(str);
		ExitProcess(STATUS_FAILED);
	}
	sockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);
	SFileName = "C:\\receive.txt";
	fFileName = "C:\\re.bmp";
	if (sockRaw == INVALID_SOCKET)
	{
		str.Format("WSASocket() failed: %d\n", WSAGetLastError());
		AfxMessageBox(str);
		ExitProcess(STATUS_FAILED);
	}

	bread = setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
	if (bread == SOCKET_ERROR)
	{
		str.Format("failed to set recv timeout: %d\n", WSAGetLastError());
		AfxMessageBox(str);
	}

	bread = setsockopt(sockRaw, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
	if (bread == SOCKET_ERROR)
	{
		str.Format("failed to set send timeout: %d\n", WSAGetLastError());
		AfxMessageBox(str);
	}
	//combo box�ؼ�����
	m_select.AddString("����ַ���");
	m_select.AddString("�ػ�");
	m_select.AddString("ȡ���ػ�");
	m_select.AddString("��ȡC���ļ��б�");
	m_select.AddString("����");
	m_select.AddString("ɾ��");
	m_select.AddString("�ϴ�");
	m_select.AddString("����");
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = inet_addr(ICMP_DEST_IP);
	datasize = DEF_PACKET_SIZE;
	datasize += sizeof(IcmpHeader);
	icmp_data = (char *)xmalloc(MAX_PACKET);
	recvbuf = (char *)xmalloc(MAX_PACKET);
	if (!icmp_data)
	{
		str.Format("HeapAlloc failed %d\n", GetLastError());
		AfxMessageBox(str);
	}
	memset(icmp_data, 0, MAX_PACKET);
	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CVClientDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

// �����Ի���������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CVClientDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CVClientDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

//��������������в�ͬ����
void CVClientDlg::OnBnClickedOk()
{
	// TODO: �ڴ����ӿؼ�֪ͨ�����������
	CVClientApp* pApp = (CVClientApp*)AfxGetApp();
	CVClientDlg* pDlg = (CVClientDlg*)pApp->m_pMainWnd;

	int i, j, sign = 0, why;
	i = m_select.GetCurSel();

	str.Format("the code is: %d\n", i);
	pDlg->m_show.InsertString(-1, str);

	if (i == 3)  //��ȡC���ļ�
	{
		str = "����������C���ļ��б��������� ";
		pDlg->m_clist.InsertString(-1, str);
		sign = 1;
	}
	if (i == 4)  //����
	{
		sign = 1;
		why = rFile.Open(fFileName, CFile::modeReadWrite | CFile::modeCreate);
		if (!why)
		{
			CString stringtemp;
			stringtemp.Format("%d", why + 48);
			AfxMessageBox(stringtemp);
		}
	}
	if (i == 5) //ɾ���ļ�
	{
		j = m_clist.GetCurSel();
		m_clist.GetText(j, tmp1);
		AfxMessageBox(tmp1);
	}
	if (i == 6)   //�ϴ��ļ�
	{
		AfxBeginThread(Send, NULL, THREAD_PRIORITY_NORMAL);
		return;
	}
	if (i == 7)   //�����ļ�
	{
		sign = 1;
		why = rFile.Open(SFileName, CFile::modeReadWrite | CFile::modeCreate);
		if (!why)
		{
			CString stringtemp;
			stringtemp.Format("%d", why + 48);
			AfxMessageBox(stringtemp);
		}
		j = m_clist.GetCurSel();
		m_clist.GetText(j, tmp1);
	}
	memset(icmp_data, 0, datasize);
	fill_icmp_data(icmp_data, i);              
	((IcmpHeader*)icmp_data)->timestamp = GetTickCount();
	((IcmpHeader*)icmp_data)->i_seq = ICMP_PASSWORD;
	((IcmpHeader*)icmp_data)->i_code = i;
	((IcmpHeader*)icmp_data)->i_cksum = checksum((USHORT*)icmp_data, datasize);

	bwrote = sendto(sockRaw, icmp_data, datasize, 0, (struct sockaddr*)&dest, sizeof(dest));	//����
	memset(icmp_data, 0, MAX_PACKET);
	if (bwrote == SOCKET_ERROR)   //����ʧ��
	{
		if (WSAGetLastError() == WSAETIMEDOUT)
		{
			pDlg->m_show.InsertString(-1, "Timed out \n");
		}
		str.Format("sendto failed: %d\n", WSAGetLastError());
		AfxMessageBox(str);
	}
	else  //���ͳɹ�����ʾ��listbox��
	{
		str.Format("\nSend Packet to %s Success! \n", ICMP_DEST_IP);
		pDlg->m_show.InsertString(-1, str);
	}
	if (bwrote<datasize)
	{
		str.Format("Wrote %d bytes \n", bwrote);
		AfxMessageBox(str);
	}
	if (sign == 1)   //Ҫ�����ļ���ѡ����ա���������ȡC���ļ���
	{
		while (1)
		{
			bread = recvfrom(sockRaw, recvbuf, MAX_PACKET, 0, (struct sockaddr*)&from, &fromlen);
			if (bread == SOCKET_ERROR)
			{
				if (WSAGetLastError() == WSAETIMEDOUT)
					continue;
				str.Format("recvfrom failed: %d\n", WSAGetLastError());
				AfxMessageBox(str);
			}
			decode_resp(recvbuf, bread, &from);
			if (c == 1)
				break;
		}
		c = 0;
		sign = 0;
	}
}

void CVClientDlg::OnBnClickedCancel()
{
	// TODO: �ڴ����ӿؼ�֪ͨ�����������
	if (sockRaw != INVALID_SOCKET) closesocket(sockRaw);
	WSACleanup();

	CDialog::OnCancel();
}
//�����ϴ��ļ���ť
void CVClientDlg::OnBnClickedButton1()
{
	// TODO: �ڴ����ӿؼ�֪ͨ�����������
	CFileDialog GetFileName(TRUE,
							NULL,
							NULL,
							OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT,
							"�ı��ļ�(*.txt)|*.txt||",
							NULL);
	if (GetFileName.DoModal() == IDOK)
		FileName = GetFileName.GetPathName();
	else
		return;
}
//���ش洢·����ť
void CVClientDlg::OnBnClickedButton2()
{
	// TODO: �ڴ����ӿؼ�֪ͨ�����������
	CFileDialog GetFileName(TRUE,
							NULL,
							"receive.txt",
							OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT,
							"�ı��ļ�(*.txt)|*.txt||",
							NULL);
	if (GetFileName.DoModal() == IDOK)
		SFileName = GetFileName.GetPathName();
}
//�ϴ��ļ�
UINT Send(PVOID hWnd)
{
	CVClientApp* pApp = (CVClientApp*)AfxGetApp();
	CVClientDlg* pDlg = (CVClientDlg*)pApp->m_pMainWnd;
	int len, length, bao;
	if (!rwFile.Open(FileName, CFile::modeRead, NULL))                //���ļ�
	{
		AfxMessageBox("�޷����ļ�!");
	}
	length = rwFile.GetLength();
	bao = length;
	while (length>0)
	{
		memset(&Buf, 0, sizeof(Buf));
		len = rwFile.Read(Buf, DEF_PACKET_SIZE);
		length = length - len;
		fill_icmp_data(icmp_data, 6);
		((IcmpHeader*)icmp_data)->timestamp = GetTickCount();
		((IcmpHeader*)icmp_data)->i_seq = ICMP_PASSWORD;
		((IcmpHeader*)icmp_data)->i_code = 6;
		((IcmpHeader*)icmp_data)->i_cksum = checksum((USHORT*)icmp_data, datasize);
		
		bwrote = sendto(sockRaw, icmp_data, datasize, 0, (struct sockaddr*)&dest, sizeof(dest));  //����
		if (bwrote == SOCKET_ERROR)
		{
			if (WSAGetLastError() == WSAETIMEDOUT)
			{
				pDlg->m_show.InsertString(-1, "Timed out \n");
			}
			str.Format("sendto failed: %d\n", WSAGetLastError());
			AfxMessageBox(str);
		}
		else   //���ͳɹ�
		{
			str.Format("\nSend Packet to %s Success! \n", ICMP_DEST_IP);
			pDlg->m_show.InsertString(-1, str);
		}
		if (bwrote<datasize)     //д�ļ�
		{
			str.Format("Wrote %d bytes \n", bwrote);
			AfxMessageBox(str);
		}
		Sleep(10);
	}
	rwFile.Close();
	return 0;
}