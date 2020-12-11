#pragma once
#include <windows.h>

class peLoader64
{
public:
	peLoader64();
	~peLoader64();

	bool load(BYTE* data);
};