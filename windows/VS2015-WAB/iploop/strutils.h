#pragma once

void STRTrimTrailingNullCharactersW(_Inout_ std::wstring& rstrW);

bool STRWideCharToAnsi(_In_ LPCWSTR lpszWideChar, _Out_ std::string& rstrAnsi,
	_Out_ size_t& rulNumberOfBytesWritten);
