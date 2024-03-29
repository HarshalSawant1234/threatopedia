from django.shortcuts import render
import threatopedia.check_ip as ip
import threatopedia.check_url as url
import threatopedia.check_hash as h
import threatopedia.pycountry as pc
import socket

# Create your views here.

def home(request):
	return render(request, """/home/harshal/Desktop/django-test/mscproject/threatopedia/templates/home.html""")

def result(request):
	context = {}
	not_ip = False
	not_url = False
	not_hash = False
	value = request.POST.get('search_box', None)
	try:
		if socket.inet_aton(value):
			ip_address_check_abuse = ip.check_abuse(value)
			vt_score, vt_result, network, country_code_vt = ip.check_vt(value)
			context['ip'] = value
			context['report_count'] = ip_address_check_abuse[5]
			context['confidence_of_abuse'] = ip_address_check_abuse[4]
			context['isp'] = ip_address_check_abuse[3]
			context['domain'] = ip_address_check_abuse[1]
			country_code_abuse = ip_address_check_abuse[2]
			context['country_abuse'] = pc.countries(country_code_abuse)
			context['last_reported'] = ip_address_check_abuse[6]
			context['vt_score'] = vt_score
			context['vt_result'] = vt_result
			context['network'] = network
			context['country_vt'] = pc.countries(country_code_vt)
			return render(request, """/home/harshal/Desktop/django-test/mscproject/threatopedia/templates/ip_result.html""", context)
	except:
		not_ip = True
	if not_ip == True:
		try:
			context['url'] = value
			try:
				malicious_count, vt_category, vt_result = url.check_vt(value)
				context['vt_score'] = malicious_count
				context['vt_category'] = vt_category
				context['vt_result'] = vt_result
			except:
				context['vt_score'] = "0"
				context['vt_category'] = "None"
				context['vt_result'] = "None"
			try:
				ibm_result, risk_score, ibm_categories = url.check_ibm(value)
				context['ibm_score'] = risk_score
				context['ibm_category'] = ibm_categories
				context['ibm_result'] = ibm_result
			except:
				context['ibm_score'] = "0"
				context['ibm_category'] = "None"
				context['ibm_result'] = "None"
			try:
				phish_result = 	url.is_phish(value)	
				context['phistank_result'] = phish_result
			except:
				context['phistank_result'] = "None"
			return render(request, """/home/harshal/Desktop/django-test/mscproject/threatopedia/templates/url_result.html""", context)
		except:
			not_url = True
	if not_ip == True and not_url == True:
		try:
			context['hash'] = value
			hash_result, com_file_name, vulnerability, threat_category, threat_name, malicious, md5, sha1, sha256 = h.check_hash_vt(value)
			context['hash_result'] = hash_result
			context['com_file_name'] = com_file_name
			context['vulnerability'] = vulnerability
			context['threat_category'] = threat_category
			context['threat_name'] = threat_name
			context['malicious'] = malicious
			context['md5'] = md5
			context['sha1'] = sha1
			context['sha256'] = sha256
			return render(request, """/home/harshal/Desktop/django-test/mscproject/threatopedia/templates/hash_result.html""", context)
		except:
			not_hash = True
	if not_ip == True and not_url == True and not_hash == True:
		return render(request, """/home/harshal/Desktop/django-test/mscproject/threatopedia/templates/error.html""", context)


def about_us(request):
	return render(request, """/home/harshal/Desktop/django-test/mscproject/threatopedia/templates/about_us.html""")

def htw(request):
	return render(request, """/home/harshal/Desktop/django-test/mscproject/threatopedia/templates/how_threat_o_pedia_works.html""")

	
