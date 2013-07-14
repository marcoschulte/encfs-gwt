# encfs-gwt
encfs-gwt is a modified version of encfs-java (https://github.com/mrpdaemon/encfs-java), usable as a gwt module. All filesystem-calls are modified to be asynchronous. The missing JRE classes are provided from openjdk and the JRE's crypto functionality has been reimplemented using the Standford Javascript Crypto Library (SJCL). Only read operations are supported.

## Dependencies
* Adapted version of SJCL (See https://bitbucket.org/marcoschulte/sjcl)

## License
encfs-gwt is licensed under the GNU General Public License (GPL) 3.0