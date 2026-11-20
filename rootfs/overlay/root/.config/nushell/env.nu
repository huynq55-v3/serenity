$env.PROMPT_COMMAND = {||
    let dir = ($env.PWD | str replace $env.HOME "~")
    $"(ansi green_bold)root@serenity(ansi reset):(ansi cyan_bold)($dir)(ansi reset)"
}
$env.PROMPT_INDICATOR = {|| " > " }
