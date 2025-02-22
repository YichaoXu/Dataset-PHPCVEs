# 使用 Python 3.9 作为基础镜像
FROM python:3.9-slim

# 安装 Python 依赖
RUN apt-get update && apt-get install -y wget unzip
RUN pip install cwe_tree==1.0.0 requests==2.32.3

# 设置工作目录
RUN mkdir -p /input
COPY ./caches /input
COPY ./scripts /input
WORKDIR /input

# Ensure startup.sh is executable
RUN sed -i 's/\r$//' /input/startup.sh
RUN chmod +x /input/startup.sh

# Set up volume for persistent storage
VOLUME ["/output"]

# 运行 download.py 进行下载
CMD ["/bin/bash", "/input/startup.sh", "/input", "/output"]
