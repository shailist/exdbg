#pragma once

#include <concepts>
#include <condition_variable>
#include <optional>
#include <mutex>
#include <queue>

namespace exdbg
{
	class timeout_exception : public std::runtime_error
	{
	public:
		using std::runtime_error::runtime_error;
	};

	template <typename T>
	class MessageQueue
	{
	public:
		template <typename... TArgs> requires std::constructible_from<T, TArgs...>
		void emplace(TArgs&&... args);

		template <typename U> requires std::same_as<std::decay_t<U>, T>
		void push(U&& value);

		T pop(std::optional<std::chrono::milliseconds> timeout = std::nullopt);

	private:
		std::queue<T> m_queue;
		std::mutex m_queue_mutex;

		std::condition_variable m_message_available;
	};

	template<typename T>
	template<typename... TArgs> requires std::constructible_from<T, TArgs...>
	void MessageQueue<T>::emplace(TArgs&& ...args)
	{
		std::unique_lock lock(m_queue_mutex);
		m_queue.emplace(std::forward<TArgs>(args)...);
		m_message_available.notify_one();
	}

	template<typename T>
	template<typename U> requires std::same_as<std::decay_t<U>, T>
	void MessageQueue<T>::push(U&& value)
	{
		emplace(std::forward<U>(value));
	}
	
	template<typename T>
	T MessageQueue<T>::pop(std::optional<std::chrono::milliseconds> timeout)
	{
		std::unique_lock lock(m_queue_mutex);
		if (timeout.has_value())
		{
			if (std::cv_status::timeout == m_message_available.wait_for(lock, timeout.value()))
			{
				throw timeout_exception("MessageQueue pop timed out");
			}
		}
		else
		{
			m_message_available.wait(lock);
		}

		T front = std::move(m_queue.front());
		m_queue.pop();

		if (!m_queue.empty())
		{
			m_message_available.notify_one();
		}

		return front;
	}
}
