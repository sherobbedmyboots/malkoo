# Docker container for Thug
mkdir ~/logs ~/files
chmod 777 ~/logs ~/files
sudo docker run --rm -it -v ~/logs:/home/thug/logs -v ~/files:/home/thug/files remnux/thug bash
thug -FZ -n . <site>