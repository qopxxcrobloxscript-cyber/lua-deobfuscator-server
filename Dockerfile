FROM node:18
RUN apt-get update && apt-get install -y lua5.4 lua5.1 luac git
# luac5.1 のシンボリックリンクを作成（vm_obfuscator.lua が "luac5.1" を探すため）
RUN which luac5.1 || ln -s $(which luac) /usr/local/bin/luac5.1
RUN lua5.1 -v
RUN luac5.1 -v 2>&1 || true
RUN git clone https://github.com/prometheus-lua/Prometheus.git /app/prometheus
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN mkdir -p temp
EXPOSE 3000
CMD ["node", "server.js"]
