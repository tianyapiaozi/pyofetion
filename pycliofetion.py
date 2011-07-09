#!/usr/bin/env python
from ctypes import *
from pyofetion import *
from ctypes.util import find_library
import sys
from optparse import OptionParser

libc = cdll.LoadLibrary(find_library('c'))

user = None

def USER_AUTH_NEED_CONFIRM(user):
    return user.loginStatus == 421 or user.loginStatus == 420

def USER_AUTH_ERROR(user):
    return ( user.loginStatus == 401 or user.loginStatus == 400 or
                user.loginStatus == 404 )

def fetion_user_set_st(user, state):
    user[0].state = state


def fx_login(mobileno, password):

    global user
    local_group_count = c_int(0)
    local_buddy_count = c_int(0)
    group_count = c_int(0)
    buddy_count = c_int(0)
    nonce = c_char_p(None)
    key = c_char_p(None)

    # construct a user object
    user = fetion_user_new(mobileno, password)
    # construct a config object
    config = fetion_config_new()
    # attach config to user
    fetion_user_set_config(user, config)

    # start ssi authencation, result string needs to be freed after use
    res = ssi_auth_action(user)
    # parse the ssi authencation result, if success, user's sipuri and userid are stored in user object, or else user->loginStatus was marked failed
    parse_ssi_auth_response(res, user)
    libc.free(res)

    # whether needs to input a confirm code, or login failed for other reason like password error
    if USER_AUTH_NEED_CONFIRM(user.contents) or USER_AUTH_ERROR(user.contents):
        debug_error('authencation failed')
        return 1

    # initialize configuration for current user
    if fetion_user_init_config(user) == -1:
        debug_error('initialize configuration')
        return 1

    if fetion_config_download_configuration(user) == -1:
        debug_error('download configuration')
        return 1

    # set user's login state to be hidden
    fetion_user_set_st(user, P_HIDDEN)

    # load user information and contact list information from local host
    fetion_user_load(user)
    fetion_contact_load(user, byref(local_group_count), byref(local_buddy_count))

    # construct a tcp object and connect to the sipc proxy server
    tcp = tcp_connection_new()
    if tcp_connection_connect(tcp, config.contents.sipcProxyIP, config.contents.sipcProxyPort) == -1:
        debug_error('connect sipc server %s:%d\n', config.contents.sipcProxyIP, config.contents.sipcProxyPort)
        return 1

    # construct a sip object with the tcp object and attach it to user object
    sip = fetion_sip_new(tcp, user.contents.sId)
    fetion_user_set_sip(user, sip)

    # register to sipc server
    res = sipc_reg_action(user)
    if not res:
        debug_error('register to sipc server')
        return 1

    parse_sipc_reg_response(res, byref(nonce), byref(key))
    libc.free(res)
    aeskey = generate_aes_key()

    response = generate_response(nonce, user.contents.userId, user.contents.password, key, aeskey)
    libc.free(nonce)
    libc.free(key)
    libc.free(aeskey)

    # sipc authencation, you can printf res to see what you received
    res = sipc_aut_action(user, response)
    if not res:
        debug_error('sipc authencation')
        return 1

    if parse_sipc_auth_response(res, user, byref(group_count), byref(buddy_count)) == -1:
        debug_error('authencation failed')
        return 1

    libc.free(res)
    libc.free(response)

    if USER_AUTH_ERROR(user.contents) or USER_AUTH_NEED_CONFIRM(user.contents):
        debug_error('login failed')
        return 1

    # save the user information and contact list information back to the local database
    fetion_user_save(user)
    fetion_contact_save(user)

    # these f**k the fetion protocol
    tv = timeval()
    tv.tv_sec = 1
    tv.tvusec = 0
    buf = create_string_buffer(1024)
    # 1 for SOL_SOCKET and 20 for SO_REVTIMEO
    if libc.setsockopt(user.contents.sip.contents.tcp.contents.socketfd, 1, 20, byref(tv), sizeof(tv)) == -1:
        debug_error('settimeout')
        return 1
    tcp_connection_recv(user.contents.sip.contents.tcp, buf, sizeof(buf))

    return 0

def send_message(mobileno, receiveno, message):
    # send this message to yourself
    if not receiveno or receiveno == mobileno:
        # construct a conversation object with the sipuri to set NULL to send a message to your self
        conv = fetion_conversation_new(user, None, None)
        if fetion_conversation_send_sms_to_myself_with_reply(conv, message) == -1:
            debug_error('send message "%s" to %s', message, user.contents.mobileno)
            return 1
    else:
        # get the contact detail information by mobile number, note that the result doesn't contain sipuri
        contact = fetion_contact_get_contact_info_by_no(user, receiveno, MOBILE_NO)
        if not contact:
            debug_error('get contact information of %s', receiveno)
            return 1

        # find the sipuri of the target user
        contact_cur = user.contents.contactList
        target_contact = None
        while True:
            if contact_cur.contents.userId == contact.contents.userId:
                target_contact = contact_cur
                break
            contact_cur = contact_cur.contents.next
            if contact_cur == user.contents.contactList:
                break

        if not target_contact:
            debug_error("sorry, maybe %s isn't in your contact list")
            return 1

        # do what the function name says
        daycount = c_int(0)
        monthcount = c_int(0)
        conv = fetion_conversation_new(user, target_contact.contents.sipuri, None)
        if fetion_conversation_send_sms_to_phone_with_reply(conv, message, byref(daycount), byref(monthcount)) == -1:
            debug_error('send sms to %s', receiveno)
            return 1
        else:
            debug_info('successfully send sms to %s\nyou have sent %d messages today, %d messages this mouth count', receiveno, daycount, monthcount)
            return 0
    return 0

def fx_logout():
    fetion_user_free(user)

def parse_options():
    parser = OptionParser()
    parser.add_option('-f', '--from', metavar='MOBILENO', dest='mobileno', 
            help='specify which number you will use to send a message')
    parser.add_option('-t', '--to', metavar='RECEIVENO', dest='receiveno',
            help='specify which number you will send a message to')
    parser.add_option('-p', '--password', dest='password', metavar='PASSWD',
            help='specify your account password')
    parser.add_option('-d', '--message', metavar='MESSAGE', dest='message',
            help='message you will send')
    parser.add_option('-m', dest='toself', default=False, 
            action='store_true', help='send a message to your own number')
    options,args = parser.parse_args()
    return options


if __name__ == '__main__':
    options = parse_options()
    print options
    if options.toself:
        options.receiveno = options.mobileno
    if ( not options.mobileno or not options.message 
            or not options.receiveno or not options.password ):
            print 'Usage:'
            print '\tcliofetion -f SOURCE -p PASSWORD -t DEST -d MESSAGE'
            print '\tcliofetion -f SOURCE -p PASSWORD -m -d MESSAGE'
            sys.exit(1)
    if not fx_login(options.mobileno, options.password):
        send_message(options.mobileno, options.receiveno, options.message)
        fx_logout()
