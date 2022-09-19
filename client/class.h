
// VClient.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CVClientApp: 
// �йش����ʵ�֣������ VClient.cpp
//

class CVClientApp : public CWinApp
{
public:
	CVClientApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CVClientApp theApp;