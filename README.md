# eml-insight
A command-line tool that analyzes the source code of emails in order to give you insight about their senders.

The script is strictly a passive analyzer. It doesn't take any action.

# how it works
- It looks at the headers of the email and identifies the network hops it took
- For each IP, it performs WHOIS and looks up an external API to display ISP info and abuse emails
- It ignores internal webmail hops (e.g. Google & Outlook)
- It informs you of special cases (e.g. whether an email sender is using Google) 

# how to use
- Just pass the file as a parameter to the script: `python emli.py [FILE]`, where:
- `[FILE]` is the exported source of an email, but having a `.txt` extension
- Manually inspect the results.

# faq
Why use a `.txt` extension for `.eml` files?
- When submitting email samples for abuse, `.eml` attachments are more often rejected by some servers, compared to `.txt`.
- More handy to open with a text editor.

# notes
- The script reads and writes from the `cache/` folder, located in the same folder as the script (included in `.gitignore`). All WHOIS and external API calls are cached and are considered valid for a week. 
- The script uses a free external API provided by `extreme-ip-lookup.com`. Don't abuse their service.

# todo
- Include a configuration file that would allow you to specify which strings to anonymize from the content and filenames.