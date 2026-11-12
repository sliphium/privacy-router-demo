FROM node:18-slim
RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH
WORKDIR $HOME/app
COPY --chown=user package*.json ./
RUN npm install
COPY --chown=user . .
EXPOSE 7860
CMD ["npm", "start", "--", "-p", "7860"]