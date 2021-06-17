#pragma once

template <typename T = HANDLE, T InvalidValue = INVALID_HANDLE_VALUE,
    typename DeleterT = BOOL (__stdcall *)(T),
    DeleterT fnDeleterDefault = ::CloseHandle>
class UniqueHandle
{
public:
    UniqueHandle() = default;

    explicit UniqueHandle(T handle,
        DeleterT fnDeleter = fnDeleterDefault) :
            m_handle(handle), m_fnDeleter(fnDeleter) {}

    UniqueHandle(const UniqueHandle& rOther) = delete;

    UniqueHandle(UniqueHandle&& rOther) :
        m_handle(InvalidValue)
    {
        m_handle    = rOther.m_handle;
        m_fnDeleter = rOther.m_fnDeleter;

        rOther.m_handle    = InvalidValue;
        rOther.m_fnDeleter = fnDeleterDefault;
    }   // UniqueHandle(UniqueHandle&& rOther)

    ~UniqueHandle()
    {
        if (InvalidValue != m_handle)
        {
            m_fnDeleter(m_handle);
        }   // if (InvalidValue != m_handle)
    }   // ~UniqueHandle()

    UniqueHandle& operator=(const UniqueHandle& rOther) =
        delete;

    UniqueHandle& operator=(UniqueHandle&& rOther)
    {
        if (this != &rOther)
        {
            if (InvalidValue != m_handle)
            {
                m_fnDeleter(m_handle);
            }   // if (InvalidValue != m_handle)

            m_handle    = rOther.m_handle;
            m_fnDeleter = rOther.m_fnDeleter;

            rOther.m_handle    = InvalidValue;
            rOther.m_fnDeleter = fnDeleterDefault;
        }   // if (this != &rOther)

        return *this;
    }   // UniqueHandle& operator=(UniqueHandle&& rOther)

    explicit operator bool() const
    {
        return (InvalidValue != m_handle);
    }   // explicit operator bool() const

    T Get() const
    {
        return m_handle;
    }   // T Get() const

    T* GetPtr()
    {
        return &m_handle;
    }   // T* GetPtr()

    T Release()
    {
        T hTemp = m_handle;

        m_handle = InvalidValue;

        return hTemp;
    }   // HANDLE Release()

    void Reset(T handle = InvalidValue)
    {
        if (InvalidValue != m_handle)
        {
            m_fnDeleter(m_handle);
        }   // if (InvalidValue != m_handle)

        m_handle = handle;
    }   // void Reset(T handle = InvalidValue)

private:
    T m_handle = InvalidValue;

    DeleterT m_fnDeleter = fnDeleterDefault;
};  // class UniqueHandle

typedef UniqueHandle<> UniqueValidHandle;

typedef UniqueHandle<
    HANDLE, NULL, BOOL (__stdcall *)(HANDLE), ::CloseHandle>
        UniqueNullableHandle;

typedef UniqueHandle<
    FILE*, nullptr, int(__cdecl *)(FILE*), ::fclose>
    UniqueFileStream;

#define SYS_INVALID_PROCESS_HANDLE_VALUE static_cast<HANDLE>(NULL)

typedef UniqueHandle<HANDLE, SYS_INVALID_PROCESS_HANDLE_VALUE>
    UniqueProcess;

typedef UniqueValidHandle UniqueFile;

typedef UniqueHandle<HANDLE, NULL> UniqueThread;
