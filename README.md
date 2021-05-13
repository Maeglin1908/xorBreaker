# xorBreaker

## Usage

### Example

    {} --min 1 --max 10 --type text "OgwQEVQWGxsARVJULQoGVBwEBRFUARwaEUUEERgJUwAcDABUER0SGQQJFlRV"

### Options

    -h : Print the current help

    -m/--min (optional | default: 2)
        -> set the minimum keysize

    -M/--max (optional | default: 80)
        -> set the maximum keysize
    
    -t/--type (optional | default: file | values : file,text)
        ->  set the type of input you give. 
            It can be a file, or a text between quotes.
            In case it's a text, it must be base64 encoded.
            The file too
