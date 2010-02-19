curl http://localhost:8080/scriptingserver/admin?restart
curl -H "X-Content-Name: soapserver.js" -T soapserver.js http://localhost:8080/scriptingserver/admin

curl -H "X-Content-Name: publickeyreference.js" -T ../publickeyreference.js http://localhost:8080/scriptingserver/admin
curl -H "X-Content-Name: cvc.js" -T ../cvc.js http://localhost:8080/scriptingserver/admin
curl -H "X-Content-Name: pkcs8.js" -T ../pkcs8.js http://localhost:8080/scriptingserver/admin
curl -H "X-Content-Name: cvcertstore.js" -T ../cvcertstore.js http://localhost:8080/scriptingserver/admin
curl -H "X-Content-Name: EAC2CVCertificateGenerator.js" -T ../EAC2CVCertificateGenerator.js http://localhost:8080/scriptingserver/admin
curl -H "X-Content-Name: EAC2CVRequestGenerator.js" -T ../EAC2CVRequestGenerator.js http://localhost:8080/scriptingserver/admin
curl -H "X-Content-Name: cvcca.js" -T ../cvcca/cvcca.js http://localhost:8080/scriptingserver/admin
curl -H "X-Content-Name: servicerequest.js" -T servicerequest.js http://localhost:8080/scriptingserver/admin
curl -H "X-Content-Name: cvcaservice.js" -T cvcaservice.js http://localhost:8080/scriptingserver/admin
curl -H "X-Content-Name: cvcaui.js" -T cvcaui.js http://localhost:8080/scriptingserver/admin
curl -H "X-Content-Name: dvcaservice.js" -T dvcaservice.js http://localhost:8080/scriptingserver/admin
curl -H "X-Content-Name: configureservices.js" -T configureservices.js http://localhost:8080/scriptingserver/admin
