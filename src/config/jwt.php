<?php

return [
    'key'   =>  '#sdfkw%$',
    'expire_time'   =>  config('cookie.expire') ?: 7200,
    'method'    =>  config('cookie.method') ?: 'HS256',
];