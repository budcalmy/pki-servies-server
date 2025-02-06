# Базовый образ с Python и Ubuntu
FROM ubuntu:20.04

# Установка зависимостей без интерактивных запросов
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    libsqlite3-dev \
    python3.9 \
    python3-pip \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Копируем проект в контейнер
WORKDIR /app
COPY . .

# Собираем C++ компоненты
RUN cd /app/PKI_CPP && mkdir build && cd build && cmake .. && make

# Устанавливаем Python зависимости
RUN pip3 install -r requirements.txt

# Открываем порт сервера
EXPOSE 8000

# Запуск сервера при старте контейнера
CMD ["python3", "server.py"]