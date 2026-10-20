---
type: Explanation
title: CFlix flaws explanation
description: How each intentional vulnerability of the CFlix challenge was introduced, and how it should be fixed.
tags: [security, owasp, challenge, writeup]
---

# Flaws 1 & 2: XSS

In `Startup.cs`, cookie protection was disabled:

```csharp
options.Cookies.ApplicationCookie.CookieHttpOnly = false;
```

and in the view, `Html.Raw` is used:

```asp
<div class="text">@Html.Raw(review.Content)</div>
```


# Flaw 3: SQLi

In `Services/Repositories/MediaRepository.cs`, SQL queries are misused:

```csharp
return await _context.Medias.FromSql($"SELECT Id, ImageUri, Title, Type, YouTubeId, ReleaseDate FROM Medias WHERE Title LIKE '%{query}%'")
```

The query looks valid, but C# 7 string interpolation acts here as a plain
concatenation of the `query` variable into the request. It is not "prepared"
correctly by the framework, so the following syntax should be preferred instead:

```csharp
return await _context.Medias.FromSql("SELECT Id, ImageUri, Title, Type, YouTubeId, ReleaseDate FROM Medias WHERE Title LIKE '%{@query}%'", new SqlParameter("@query", query))
// or
return await _context.Medias.FromSql("SELECT Id, ImageUri, Title, Type, YouTubeId, ReleaseDate FROM Medias WHERE Title LIKE '%{0}%'", query)
```

(In the modernized code the vulnerable call uses `FromSqlRaw` with string
concatenation; the safe fix is `FromSqlInterpolated` or a parameterized
`FromSqlRaw`.)


# Flaw 4: Misconfiguration

The first mistake on this challenge was to ship to production while leaving the
`ASPNETCORE_ENVIRONMENT=Development` environment variable in
`docker-compose.override.yml` (not visible in this version of the code). This
let the Ugly Duckling obtain important information about the environment (and
therefore reach the files on the NAS that much more easily).

The second mistake was to believe that storing the connection strings inside an
application's resources was enough to secure them.

![JustDecompile resources](images/chall_04.png)

```csharp
public Startup(IHostingEnvironment env)
{
    var builder = new ConfigurationBuilder()
        .SetBasePath(env.ContentRootPath)
        .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
        .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
        .AddFromZipRessource("settings", "appsettings.json") // <- this was the interesting line, revealing the format of the configuration file
        .AddEnvironmentVariables();
    Configuration = builder.Build();
}
```

In that case, it is better to use other means to store connection strings, such
as environment variables, which are not physically present on disk.


# Flaw 5: Mass Assignment

Here the problem is not immediately obvious, but there is one. We use the
`ProfileViewModel` object, which was initially not meant for the Edit request
but for the Index method, to display information on the `/User/Me` page. As a
result, this object accepts the `AccountType` parameter even though it is not
declared in the edit form view.

```csharp
public async Task<IActionResult> Edit(ProfileViewModel profile)
{
    if (!ModelState.IsValid)
    {
        return View();
    }

    var user = await _userManager.GetUserAsync(User);
    user.UpdateWithProfileViewModel(profile);
    await _userManager.UpdateAsync(user);

    return RedirectToAction(nameof(Index), new { profileName = "me" });
}

public static void UpdateWithProfileViewModel(this CFlixUser user, ProfileViewModel model)
{
    if (model.AccountType != AccountType.User)
    {
        user.AccountType = model.AccountType;
    }

    user.AvatarType = model.AvatarType;
    user.DisplayName = model.DisplayName;
}
```

It is better to create a second, dedicated model to control exactly which fields
are taken from the user.


# Flaw 6: LFI - Directory Traversal
>  **Never trust user input!**

Here a directory traversal was introduced simply by reusing the parameters
received without validating them first.

```csharp
public IActionResult Index(string mediaId, string image)
{
    if (string.IsNullOrWhiteSpace(mediaId) || string.IsNullOrWhiteSpace(image))
    {
        return NotFound();
    }

    var path = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "images", mediaId, image);
    if (!System.IO.File.Exists(path))
    {
        return NotFound();
    }

    var bytes = System.IO.File.ReadAllBytes(path);

    return File(bytes, "application/octet-stream");
}
```

If you need to do this kind of thing, ASP.NET Core offers a much safer way.
In `Startup.cs`:
```csharp
        public void ConfigureServices(IServiceCollection services)
        {
            // ...
            services.AddSingleton(_hostingEnvironment.WebRootFileProvider);
        }
```
And in the controller:
```csharp
public class ViewerController : Controller
{
    private readonly IFileProvider _fileProvider;

    public ViewerController(IFileProvider fileProvider)
    {
        _fileProvider = fileProvider;
    }

    public IActionResult Index(string mediaId, string image)
    {
        var fileInfo = _fileProvider.GetFileInfo(Path.Combine("images", image));
        if (!fileInfo.Exists)
        {
            return NotFound();
        }

        return PhysicalFile(fileInfo.PhysicalPath, "application/octet-stream");
    }
}
```
The [PhysicalFileProvider](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/file-providers)
class lets you browse the local file system safely. In particular, it scopes the
browsable tree to a specified directory and all of its descendants.


# Flaws 7 & 8

These flaws are not discussed here; they had no direct relation to programming.


# Flaw 9: Component with a known vulnerability — CVE-2017-5941

The flaw exploited here is in the Node.js code. We use the `node-serialize`
library, which has a vulnerability allowing arbitrary JS execution through IIFEs
(Immediately Invoked Function Expressions). See
[CVE-2017-5941](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5941)
for more information.

```javascript
var serialize = require('node-serialize');
app.post('/cookie', function (req, res) {
    try {
        var aspCookie = serialize.unserialize(req.body);
        res.send(aspCookie);
    } catch (error) {
        res.status(500).send(error.message);
    }
});
```

So this library should be avoided and, more generally, always be careful with
data received from the user.


# Flaw 10

This time the problem is in the `vm` library. Even though it is part of Node, it
has a known issue that allows escaping the context you create, landing directly
in the application's main context.

```javascript
var vm = require("vm");

var script = new vm.Script(arg.arg);
var context = new vm.createContext({});
var t = script.runInNewContext(context);
```

The `vm2` library should be preferred, as it is safer by default.


# Flaw 11: Binary exploit

This time we have a piece of C code at our disposal. It has a problem: it does
not check the length of the data entered by the user, which makes a buffer
overflow very easy.

```C
int main(int argc, char **argv)
{
    printf(":O tu es dans le Monde à l’envers, essayes d'en sortir !\n");

    char buffer[320];
    int size, i;

    scanf("%s", buffer); // <- here we have a problem, the user input must be validated
    size = strlen(buffer);

    printf("Tu viens de saisir : %s\n", buffer);

    return 0;
}
```


# Flaw 12: XSS again :)
