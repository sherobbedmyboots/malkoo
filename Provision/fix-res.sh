#!/bin/bash
# Increase the resolution of a VM:

# Install dependencies
sudo apt-get install xvfb xfonts-100dpi xfonts-75dpi xfstt

# Set resolutions in grub
sed -i 's/#GRUB_GFXMODE=640x480/GRUB_GFXMODE=1280x960,1280x800,1280x720,1152x768,1152x700,1024x768,800x600\\nGRUB_PAYLOAD_LINUX=keep/' /etc/default/grub

# Update grub
sudo update-grub
