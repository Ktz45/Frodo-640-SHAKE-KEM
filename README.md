# FrodoKEM
This is an sample implementaion of Frodo KEM server. Created for ~~ENPM 657 HW-04~~ CMSC 656 Final PRoject.

## Description

In this assignment you will be breaking a post-quantum KEM: FrodoKEM(you can access the specification document here

Links to an external site.). In a real deployment scenario you won't be able to attack it so easily (if you can though please submit a paper to advance our knowledge :)) so we are tinkering with the scheme a bit. In particular we are removing Fujisaki-Okamoto transformation that gives the scheme CCA-security. Similar to HW1, we are hosting an API for FrodoKEM without FO transform that uses AES-CBC as the underlying symmetric key encryption scheme at http://sp25cmsc656.cs.umd.edu:5001/

(Note that the port number is different this time)Links to an external site.

Your task is to find the FrodoKEM secret associated with your UID(yes it matters this time) through interaction (essentially using the API as a decryption oracle)

There are 3 defined interaction points for the API:

1. `/checks returns` a message indicating if the server is up and running (basically a health check if you are having issues connecting).
2. `/1st-interface` takes your UID as input, generates a Frodo key pair and returns the public key to you. WARNING: Unlike HW1, the server is stateful now so it will keep track of everyone's secret independently. Make sure to use the same public key everytime! For people working in groups, choose a single UID at the start and use that one throughout the assignment.
3. `/2nd-interface` takes an input of your UID and a ciphertext generated using FrodoKEM public key (i.e. the secret you encapsulated) and outputs another ciphertext that is encrypted using AES-CBC where the key is the secret you chose.
4. `/3rd-interface` acts as a way of verifying your result where on input of your UID and your found secret, tells you if you are correct or not.

Once again everything is basically running through JSON requests/responses. For this reason, any programming language you are comfortable with is fine.  The UID is standard UTF-8 string whereas everything else will be in hexadecimal strings. You can also see the format of request/responses on `http://sp25cmsc656.cs.umd.edu:5001/docs`

Links to an external sit if you try to access it through a web browser. You can adapt the code you had for your HW1 for new interfaces but once again we will give a template code if don't want to deal with the network engineering part.

I am doing the obligatory CS Department VPN warning here. Some of you managed to connect it last time so I don't know, it might work again but not work it either.  

For this assignment you need to submit a .zip file that includes your attack source code and a document that contains your and possibly your teammates' names,  the retrieved secret, the UID you used, how to run your code, and any resources you used.

Template code is in template.py.

Good luck everyone!
