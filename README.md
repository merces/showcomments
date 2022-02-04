# ShowComments

A Simple IDA Pro plugin that shows the comments in a database

## Installation

Copy the file `showcomments.py` to the `plugins` folder under IDA Pro installation path.

# Usage

Select an `IDA View` tab in IDA and go to `Edit->Plugins->ShowComments` or just press `Ctrl`+`Alt`+`C`.

![gif](showcomments.gif)

## Features

- Support for regular and repeatable comments.
- Double click an address to follow it in IDA View.
- Click the headers to sort.

## FAQ

1. How can I only show the user added comments?

I found no way in IDA to filter these comments. A workaround is to always set repeatable comments and use ShowComments to sort by them.

2. Does it recognize function comments?

Yes

3. What IDA versions are supported?

I've only tested with 7.5 and 7.6. Please, let me know if it works with a different version.