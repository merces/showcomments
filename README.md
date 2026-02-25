<p align="center">
  <img src="/assets/logo.png" alt="Logo" />
</p>

# ShowComments

IDA Pro plugin to display and search comments in the database.

## Installation

The recommended way is to use the [hcli](https://hcli.docs.hex-rays.com/getting-started/installation/) tool:

```shell
hcli plugin install showcomments
```

Alternatively, copy `showcomments.py` to the `plugins` directory under your IDA Pro installation path or your IDA user directory.

## Usage

From an IDA View, Hex View, or Pseudocode window, go to **Edit ▸ Plugins ▸ ShowComments** or press `Ctrl+Alt+C`.

![Screenshot](/assets/showcomments.png)

## Features

- Supports regular, repeatable, function, anterior, and posterior comments
- Filter comments with regular expressions
- Double-click an address to jump to it in IDA
- Click table headers to sort columns

## FAQ

### 1. Can I filter only user-added comments?

IDA does not currently provide an API to distinguish user-added comments from other types.

As a workaround, you can use repeatable comments consistently and then sort by them in ShowComments.

### 2. Which IDA versions are supported?

The plugin has been tested with IDA versions >= 9.2. It may work with other versions, but this has not been verified.
