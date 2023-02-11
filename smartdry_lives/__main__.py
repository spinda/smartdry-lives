# vim: set tw=99 ts=4 sts=4 sw=4 et:

from .firmware.wifi import extract_wifi_data

with open('smartdry-2023-wifi.bin', 'rb') as input_image_file:
    image = bytearray(input_image_file.read())

extract_wifi_data(image, {
    'ssid': b'Moaphioth',
    'password': b'nfXLcu7o6G0wZV23',
})

with open('smartdry-2023-wifi-patched.bin', 'wb') as output_image_file:
    output_image_file.write(image)

#entry_prefix = b'\x02\x42\x03\x80'
#ssid = b'CurryPlace'
#print(generate_ssid_entry(entry_prefix, ssid).hex(' '))
