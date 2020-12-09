**ESP32-RSA**
*Data Integrity and Security in Communication*
* Exam Work ProjectData Integrity and Security in CommunicationIn
* this project you shall make a safe and secure communication using SHA-256,
* AES-256 and RSA-512 between two nodes according to the requirements below.
* **Requirements:**
* 1.It shall be possible to have a menu system on the client for user interaction
* 2.The client shall be able to change the state of the built in LED of the server
* 3.The client shall be able to read the temperature from the server and display it in the terminala.If you use ESP32, there is an internal sensor in its chipb.
* If you use Teensy 3.5, you should connect a temperature sensor to the microcontroller
* 4.The communication between the nodes shall be protected using SHA-2565.Exchanging of the actual data between the nodes shall be secured using AES-2566.Before transferring any * * actual data, authentication and session establishment are required
* 7.For each session a random AES key shall be used
* 8.The random AES key shall be shared using RSA-512
* 9.The authentication and session establishment shall be done and secured using RSA-512
* 10.The session between the nodes shall get expired after 1 minute if there is no communicationbetween the nodes.
* In this case an automated reauthentication is required.
* **ProtocolDevices**
* *Alain Alejandro De La Bassi and Lucas Olsson TCP/IP* 
