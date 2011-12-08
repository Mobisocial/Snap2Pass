These examples show you how to use JOID. You can also look in the
unit tests (/trunk/test) for code inspiration.

Build these examples via normal 'ant build'


./server
 
  OpenID provider code. Deploy the jode_examples.war file into your
  favorite servlet container.

  If your server doesn't run on port 8080, please change the example
  files (Associate and Authenticate.java) to the correct port.


./consumer

  These examples on how to write an OpenId consumer (a relying party)
  communicate with an OpenId server.

  First use Associate.java to associate a common secret with the server.
  Then use Authenticate.java to authenticate with the server using this
  shared secret.


./scripts 

   contains scripts to run the associate and authenticate consumer clients:

   Example use:

     $ cd scripts
     $ ./associate.sh file.txt
     Results written into [path]/file.txt

     $ ./authenticate.sh file.txt

