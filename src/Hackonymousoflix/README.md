# Hackonymousoflix

This container is the attacker's server in the overall scenario.

It groups challenges 9, 10 and 11:

- La contre-attaque (Shingeki no Kyojin): exploiting JavaScript deserialization in Node.js
- La vérité éclate (House of Cards): escaping a JavaScript jail
- C étrange tout cela (Stranger Things): exploiting a binary written in C

NB: the web server behind challenge 9 can also be used by challenges 1 and 2
(for the XSS flaws). However, for those two challenges to work correctly it must
be exposed over HTTPS (Chrome blocks insecure XHR requests), which means going
through the reverse-proxy!

## Challenge details

### Challenge 9: La contre-attaque (Shingeki no Kyojin)

The goal of this challenge is to exploit the old `https://{hackonymousoflix}:1337/cookie`
route still present in the server code, in order to recover the credentials
needed to reach the next challenge.

> Remember his XSS on Better Call Saul and Game of Thrones? Well, we think we
> found a flaw in it!
>
> It looks like a v1 of his service is still available and exploitable. To do
> so, send a JSON POST request to `https://{hackonymousoflix}:1337/cookie`.
>
> Oh! From what we know, his service runs on Node.js and it seems to have
> something to do with deserialization... Good luck!

NB: the `https://{hackonymousoflix}:1337/cooooookie` route is used by challenges
1 and 2 (for the XSS flaws).


### Challenge 10: La vérité éclate (House of Cards)

To reach this challenge you must use the information found in the previous one,
so you have to connect over SSH on port 845.

> We needed a bit of time to recover from our emotions, but it should be fine
> now. You will have to manage to get out of this JS vm — to work, sire!

Once connected, you notice you do not get a regular bash shell but a very
peculiar environment. You have to find how to escape it to read the source of
this shell (`vm.js`) and thus find the password that unlocks the last command,
granting access to a real bash.

### Challenge 11: C étrange tout cela (Stranger Things)

Now that we have a bash shell, one last little thing remains: read the
`MyLittleToDoList.txt` file in the `will.byers` user's home directory.

> Come on, make it up and do what is needed to impersonate will and you will get
> access to this to-do list. Something tells me we are not far from the end!

To do this, you have to exploit the `exploit` binary, since it has the
permissions required to read the file.

## Build & Run

You can run this container stand-alone with the following commands:

```bash
docker build -t hackonymousoflix .
docker run --rm -p 1337:1337 -p 845:845 -d hackonymousoflix
```
