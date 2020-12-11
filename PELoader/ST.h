#pragma once

template <typename TARGET>
class ST
{
public:
	ST() {}
	virtual ~ST() {}
	static TARGET* getInstance()
	{
		if (m_pInstance == nullptr)
		{
			m_pInstance = new TARGET;
		}
		return m_pInstance;
	}
	static void Destroy()
	{
		if (m_pInstance)
		{
			delete m_pInstance;
			m_pInstance = nullptr;
		}
	}
private:
	static TARGET* m_pInstance;
};

template<typename TARGET> TARGET* ST<TARGET>::m_pInstance;