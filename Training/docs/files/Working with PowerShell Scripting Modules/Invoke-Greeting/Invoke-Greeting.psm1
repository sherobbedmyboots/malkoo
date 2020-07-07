function getDayOfWeek {
    return (Get-Date).DayOfWeek
}

function sayGreeting ($day, $name){
    Write-Host Happy $day $name!
}

function DoIt {
    $names | % { $day = getDayOfWeek; sayGreeting $day $_ }
}