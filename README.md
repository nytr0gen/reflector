# reflector [<img src="https://github.com/elkokc/reflector/blob/master/screenshot/release-v2.0-blue.svg">](https://github.com/elkokc/reflector/releases/tag/2.1)

# Improvements

- Payload is URL encoded to avoid false-positives
- Detects spaces in header response
- Case Insensitive detection of payload
- Might be a bit faster
- Tests all parameters (even these with length 1 and 2)

# Description
Burp Suite extension is able to find reflected XSS on page in real-time while browsing on web-site and include some features as:
* Highlighting of reflection in the response tab.
* Test which symbols is allowed in this reflection.
* Analyze  of reflection context.
* Content-Type whitelist.

 # How to use
After plugin install you just need to start work with the tested web-application. Every time when reflection is found, reflector defines severity and generates burp issue.
![reflector usage](https://github.com/elkokc/reflector/blob/master/screenshot/reflector_demo1.gif)

Each burp issue includes detailed info about reflected parameter, such as:
* Symbols that allowed in this reflection.
* Highlighting of reflection value in response.
* Reflection context analyze.

# Reflection navigation
Navigation by arrow buttons in the response tab.
![reflector usage](https://github.com/elkokc/reflector/blob/master/screenshot/navigation.gif)

# Settings
* Scope only - allow reflector to work only with a scope added websites.
* Agressive mode - reflector generates additional request with a test payload .
* Check context - activate check context mode.

Moreover you can manage content-types whitelist with which  reflector plugin should work. But if you will use another types except text/html,  this can lead to slowdowns in work.
![reflector usage](https://github.com/elkokc/reflector/blob/master/screenshot/settings.png)

# How to compile
Compiled by jdk 1.8

Example:

```
javac -d build ./src/burp/*.java
jar cf plugin.jar -C build ./burp
```

# Authors
* Shvetsov Alexandr (GitHub: ![shvetsovalex](https://github.com/shvetsovalex))
* Dimitrenko Egor (GitHub: ![elkokc](https://github.com/elkokc))
