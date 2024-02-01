# Kernel Auth Adapter Lite
This is a light version of Kernel auth adapter. All the spring dependencies are marked as provided. 
It is expected that light version auth adapter uses the spring dependencies of the MOSIP applications. This avoids spring
dependencies version conflict when integrated with any spring boot application. 

## Overview
Auth adapter is a package that needs to be injected into Mosip's applications exposing REST API's inorder to secure them.

## Usage
Add the Auth Adapter module to your project as a maven dependency
```
	<dependency>
   		<groupId>io.mosip.kernel</groupId>
   		<artifactId>kernel-auth-adapter</artifactId>
   		<version>${project.version}</version>
   	</dependency>
```
