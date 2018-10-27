from flask import Flask, render_template, request
from desEncryptor import DES

app = Flask(__name__, template_folder='templates', static_folder='static')


# Check if entered value is hex:
def is_hex(string):
    try:
        int(string, 16)
        return True
    except ValueError:
        return False


# Get hex value from entered string
def get_hex(text):
    text_byte_array = list(map(bin, bytearray(text, encoding='utf-8')))
    text_byte_array_string = ''.join([foo[2:] for foo in text_byte_array])
    return str(hex(int(text_byte_array_string, 2))[2:].upper())


def run_des(msg, password, action):
    des_run = {'Values': [],
               'Keys': [],
               'Cipher': None
               }
    des = DES()
    code = des.run(msg, password, action)

    des_run['Cipher'] = des.bin_2_formatted_hex(code, fixed_length=False)
    des_run['Keys'] = [des.bin_2_formatted_hex(des_key, length=12) for des_key in des.keys]
    des_run['Keys'].insert(0, '-')

    for foo in range(len(des.rounds)):
        bits = des.rounds[foo][0]
        initial_round = des.bin_2_formatted_hex(bits)

        des_run['Values'].append({'left_rounds': [initial_round[:8]],
                                  'right_rounds': [initial_round[8:]]})

        for i in range(16):
            des_round = des.bin_2_formatted_hex(des.rounds[foo][i + 1])

            des_run['Values'][foo]['left_rounds'].append(des_round[:8])
            des_run['Values'][foo]['right_rounds'].append(des_round[8:])

    return des_run


# Display homepage:
@app.route('/')
def load_home_page():
    return render_template('base.html')


# Display data from DES calculations:
@app.route('/', methods=['POST'])
def check_input():
    message = request.form['message']
    key = request.form['key']

    # Errors:
    # 1 - empty message or key field
    # 2- key is not hex value

    if message or key is not None:

        if not is_hex(key):
            return render_template('base.html', error_no='2')
        else:
            errors = list()
            if not is_hex(message):
                message = get_hex(message)
                errors.append('Message was not hex so it was converted to hex value which is: {}'.format(message))
            if len(key) > 16:
                key = key[:16]
                errors.append('Key was longer than 16 symbols, it was shortened to: {}'.format(key))
            # Check if there are errors:
            errors = None if len(errors) == 0 else errors
            action = request.form['action_options']
            print(action)
            if action == 'encrypt':
                encryption_values = run_des(message, key, action)
                return render_template('base.html',
                                       print_action=action,
                                       message=message,
                                       key=key,
                                       encryption_values=encryption_values,
                                       errors=errors)
            elif action == 'decrypt':
                decryption_values = run_des(message, key, action)
                return render_template('base.html',
                                       print_action=action,
                                       message=message,
                                       key=key,
                                       decryption_values=decryption_values,
                                       errors=errors)
            else:
                encryption_values = run_des(message, key, 'encrypt')
                decryption_values = run_des(encryption_values['Cipher'], key, 'decrypt')
                return render_template('base.html',
                                       print_action='both',
                                       message=message,
                                       key=key,
                                       encryption_values=encryption_values,
                                       decryption_values=decryption_values,
                                       errors=errors)
    else:
        return render_template('base.html', error_no='1')


if __name__ == '__main__':
    app.run()
