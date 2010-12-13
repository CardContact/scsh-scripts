set READER=OMNIKEY%%20CardMan%%205x21%%200
:loop
curl --data-binary @CardCustomizationRequest.xml http://localhost:8080/scriptingserver/se/reader/%READER%
goto loop

