This is a re-write of the pyvault script I wrote with hvac, for my personal usage.

hvac is a wrapper python module which is used to interact with the hashicorp vault api.

However I found hvac extremely difficult to use and action is limited to bugs, if there is bug my script breaks.
Hence I have decided to interact directly with the api endpoint of hashicorp vault with requests module.

With requests module I design the functions I need and easier to troubleshoot and modify since I wrote the functions.
I found there is no value add or advantage in using api wrapper such as hvac.

The hashicorp vault api documentation is easier to understand and more complete than hvac's documentation, and more real examples.
I can use api client like postman or insomnia to check the api, in conclusion use api calls directly and do not use any wrapper.# pyvault2
