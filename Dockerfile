FROM python:3.11-slim

# 设置工作目录
WORKDIR /app

# 安装依赖 (关键修正：补全了 aiofiles 和 python-multipart)
RUN pip install --no-cache-dir fastapi uvicorn cryptography pydantic aiofiles python-multipart

# 复制所有代码文件
COPY main.py .
COPY index.html .
COPY style.css .
COPY app.js .
COPY flags.js .

# 创建数据目录
RUN mkdir -p /app/data

# 暴露端口
EXPOSE 9111

# 启动命令
CMD ["python", "main.py"]