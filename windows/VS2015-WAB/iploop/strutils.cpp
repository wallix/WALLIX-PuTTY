#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers

#include <Windows.h>

#include <string>

void STRTrimTrailingNullCharactersW(_Inout_ std::wstring& rstrW)
{
	size_t const ulPos = rstrW.find_last_not_of(L'\0');
	rstrW.resize((std::string::npos == ulPos) ? 0 : ulPos + 1);
}   // void STRTrimTrailingNullCharactersW(_Inout_ std::wstring& rstrW)

void STRTrimTrailingNullCharactersA(_Inout_ std::string& rstrA)
{
	size_t const ulPos = rstrA.find_last_not_of('\0');
	rstrA.resize((std::string::npos == ulPos) ? 0 : ulPos + 1);
}   // void STRTrimTrailingNullCharactersA(_Inout_ std::string& rstrA)

static bool STRWideCharToMultiByte(_In_ UINT uCodePage,
	_In_ LPCWSTR lpszWideChar, _Out_ std::string& rstrMultiByte,
	_Out_ size_t& rulNumberOfBytesWritten)
{
	int const nRequiredSize =
		WideCharToMultiByte(
			/*CodePage          =*/ uCodePage,
			/*dwFlags           =*/ 0,
			/*lpWideCharStr     =*/ lpszWideChar,
			/*cchWideChar       =*/ -1,
			/*lpMultiByteStr    =*/ NULL,
			/*cbMultiByte       =*/ 0,
			/*lpDefaultChar     =*/ NULL,
			/*lpUsedDefaultChar =*/ NULL
		);
	if (!nRequiredSize)
	{
		rstrMultiByte.clear();

		rulNumberOfBytesWritten = 0;

		return false;
	}   // if (!nRequiredSize)

	rstrMultiByte.resize(nRequiredSize);

	int const nNumberOfBytesWritten =
		WideCharToMultiByte(
			/*CodePage          =*/ uCodePage,
			/*dwFlags           =*/ 0,
			/*lpWideCharStr     =*/ lpszWideChar,
			/*cchWideChar       =*/ -1,
			/*lpMultiByteStr    =*/ &rstrMultiByte[0],
			/*cbMultiByte       =*/ nRequiredSize,
			/*lpDefaultChar     =*/ NULL,
			/*lpUsedDefaultChar =*/ NULL
		);
	if (!nNumberOfBytesWritten)
	{
		rstrMultiByte.clear();

		rulNumberOfBytesWritten = 0;

		return false;
	}   // if (!nNumberOfBytesWritten)

	STRTrimTrailingNullCharactersA(rstrMultiByte);

	rulNumberOfBytesWritten = static_cast<size_t>(nNumberOfBytesWritten);

	return true;
}   // bool STRWideCharToMultiByte(_In_ UINT uCodePage,
	//     _In_ LPCWSTR lpszWideChar, _Out_ std::string& rstrMultiByte,
	//     _Out_ size_t& rulNumberOfBytesWritten)

bool STRWideCharToAnsi(_In_ LPCWSTR lpszWideChar, _Out_ std::string& rstrAnsi,
	_Out_ size_t& rulNumberOfBytesWritten)
{
	return STRWideCharToMultiByte(CP_ACP, lpszWideChar, rstrAnsi,
		rulNumberOfBytesWritten);
}   // bool STRWideCharToAnsi(_In_ LPCWSTR lpszWideChar,
	//     _Out_ std::string& rstrAnsi, _Out_ size_t& rulNumberOfBytesWritten)
