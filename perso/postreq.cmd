set READER=OMNIKEY%%20CardMan%%205x21%%200
curl --data-binary @CardCustomizationRequest.xml http://localhost:8080/se/reader/%READER%

