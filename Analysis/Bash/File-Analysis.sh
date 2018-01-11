# Carve Files
foremost -v -i $filename

Strings
Exiftool

# Examine Binary
binwalk -B $filename
binwalk -e $filename

# Hex to Binary
xxd -r -p input.txt output.bin
