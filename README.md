# jirafs

jirafs is a 9P fileserver that presents JIRA as a filesystem. It tries to be feature-complete without getting in the way.

jirafs supports both username/password (basic authentication) login, and oauth 1.0 login to JIRA.

## OAuth

In order to use oauth, you must generate a key pair for jirafs:
```plain
openssl genrsa -out private_key.pem 4096
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

After setting this up, you will have to set up a generic application link in JIRA, entering arbitrary URL's (they don't matter), a consumer key and the public key generated above. Once done, starting jirafs with `-oath -ckey consumer_key -pkey private_key.pem` should work, requesting that you go through the OAuth verification step (note that -ckey is the literal key, not a path to a key file).

## Username/password (basic) auth

Simply start jirafs with the `-pass` option.

## Mounting jirafs

On Linux, you can mount jirafs with the following (assuming it is running on localhost:30000):
```plain
sudo mount -t 9p -o trans=tcp,port=30000,noextend,sync,dirsync,nosuid,tcp 127.0.0.1 /mnt/jira
```

Beware that v9fs, the 9P kernel support for Linux, has a few bugs. One is that it does not feed through the OTRUNC opening option properly, meaning that some "echo wee > file" becomes "echo wee >> file" instead. Another is that it does not handle large directory listings well, so keep maxlisting to about 100. The patches to fix these issues are on their way, but it will probably take a while before you'll get the update.

These issues are due to v9fs not getting much use as a "normal" 9P client, but let's change that!

On MacOSX, there are two options:
* You can use plan9port which provides 9pfuse. First install [FUSE for macOS](https://osxfuse.github.io/). Then install [plan9port](https://9fans.github.io/plan9port/). You can then use 9pfuse to mount. Beware, however, that stock 'ls' on MacOSX won't work to show the available directory files--you have to use '9 ls', '9 lc' etc.
```plain
cd jirafs; go build; ./jirafs -pass -url=https://jira.example.com
# then after entering credentials, open another terminal in the parent directory you want for accessing JIRA:
9pfuse 'tcp!localhost!30000' my-jira; cd my-jira; 9 lc projects
```
* You can use [Mac9P](https://github.com/kennylevinsen/mac9p). Follow the install instructions.

## Disclaimer

jirafs comes without any warranties. The jirafs directory structure may change at random until an optimal shape has been reached.

# Structure

```plain
/
   ctl
   projects/
      ABC/
         components
         issuetypes
         issues/
            1/ # ABC-1
               ...
            ...

      DEF/
         ...
      ...
   issues/
      new/
         ctl
         description
         project
         summary
         type
      ABC-1/
         assignee
         comments/
            1/
               author
               updated
               created
               comment
            2/
               ...
            ...
            comment
         components
         creator
         ctl
         description
         key
         labels
         links
         priority
         progress
         project
         raw
         reporter
         resolution
         status
         summary
         transition
         type
         worklog/
            1/
               author
               started
               time
               comment
            ...
      ABC-2/
         ...
      ...

```

## Files worthy of note

## ctl

A global control file. It supports the following commands:

* search search_name JQL

If successful, a folder named search_name will appear at the jirafs root. `ls`'ing in the folder updates the search. The search does not update when simply trying to access an issue in order to avoid significant performance issues.

* pass-login

Re-issue a username/password login using the initially provided credentials.

* set name val

Sets jirafs variables. Currently, max-listing is the only variable, which expects an integer.


## projects/ABC/issues

A convenience view of only the issues present in the project. They are listed without their project key. Their structure is similar to that of an issue in issues/

## issues/new

New is a folder that creates a new skeleton issue when entered. It only contains a minimal set of files necessary to create the issue. Once all fields have been filled out, writing "commit" to the ctl file will cause the issue to be created. The issue folder will change to be that of a created issue, with all files available. Read the "key" file to figure out what issue key your issue received.

### issues/ABC-1/comments

A folder containing comments for the issue. Writing to the comment file creates a new comment. Writing to an existing comment changes it. This structure may change in the future.

### issues/ABC-1/components

A list of components this issue applies to. Writable. Note that the component names are case sensitive, and must be match an existing component for the project.

### issues/ABC-1/ctl

A command file. On a new issue, the only accepted command is "commit", which creates the issue with the provided parameters. For existing issues, the only accepted command is "delete". In the future, more commands may be made available for things that map poorly to files.

### issues/ABC-1/links

Issue links in the form of "INWARD-ISSUE OUTWARD-ISSUE RELATIONSHIP", such as "ABC-1 ABC-2 Blocks". Writable.

### issues/ABC-1/raw

The raw JSON issue object. Writable. Expects the written data to be JSON, and the write will be pushed as an issue update.

### issues/ABC-1/status

When writing to the status file, jirafs will fetch the relevant workflow graph and trace the shortest path from the current status to the requested status, issuing the necessary transitions in order.

### issues/ABC-1/transition

A list of currently possible transitions. Writing to the file executes the transition. See `status` for a more convenient way of changing issue status.
