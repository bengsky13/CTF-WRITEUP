## Juggernaut of Wicked Tyranny


```
We're given laravel project and it has binary file that will executed
and the service are
http://ctf.protergo.party:10004/
```

### Reconnaissance
We can refer to this https://laravel.com/docs/10.x/structure to learn about laravel
at this moment we just need to read the
- Routes
- Controller

We can easily using php artisan cli to gather the routes information
```
php artisan route:list
```

```
GET|HEAD        api/portal_login  portal_login.index › Api\LoginController@index
POST            api/portal_login  portal_login.store › Api\LoginController@store
GET|HEAD        api/portal_login/{portal_login} . portal_login.show › Api\LoginController@show
PUT|PATCH       api/portal_login/{portal_login} . portal_login.update › Api\LoginController@update
DELETE          api/portal_login/{portal_login} . portal_login.destroy › Api\LoginController@destroy
GET|HEAD        api/portal_register . portal_register.index › Api\RegisterController@index
POST            api/portal_register . portal_register.store › Api\RegisterController@store
GET|HEAD        api/portal_register/{portal_register} . portal_register.show › Api\RegisterController@show
PUT|PATCH       api/portal_register/{portal_register} . portal_register.update › Api\RegisterController@update
DELETE          api/portal_register/{portal_register} . portal_register.destroy › Api\RegisterController@destroy
GET|HEAD        home  home › HomeController@home
GET|HEAD        portal_login  index › HomeController@index
GET|HEAD        portal_register . register › HomeController@register
```
sort of explanation
if we access base_url + routes so the controller will take care of the logic

in this case if we access 

POST http://ctf.protergo.party:10004/api/portal_login the request will be send to Api\LoginController@store
in app\Http\Controllers\Api\LogicController function name store
```php
$validator = Validator::make($request->all(), [
    'username'     => 'required',
    'password'     => 'required',
]);

if ($validator->fails()) {
    return response()->json($validator->errors(), 422);
}

$credentials = request(['username', 'password']);


if (! $token = auth()->attempt($credentials)) {
    return new LoginResource(false, 'OK', $credentials);
}

$resp = [
    'access_token' => $token,
    'token_type' => 'bearer',
    'expires_in' => auth()->factory()->getTTL() * 60
];

// Cookie::get('jwt_token');
// Cookie::queue('auth', $token, 60);

return new LoginResource(true, 'OK', $resp);
```
this logic will be executed

this challenge similar to Just-Wiggle-Tools but to obtain the private key and passphrase we need some of reverse engineer

look at GET / it will send it to the controller HomeController@dashboard 
```php
public function dashboard()
{
    if (file_exists("/var/www/html/storage/jwt/private.pem")){
        return view('dashboard');
    }
    else{
        print_r(shell_exec("/var/www/html/storage/jwt/chall " . env('JWT_PASSPHRASE', ''))); // BINARY FILE
    }
}
```

here is the private key generation

and how about the passphrase ?
thats why we need reversing

now we need to reversing the binary file **/var/www/html/storage/jwt/chall**

using ghidra
```cpp
void processEntry entry(undefined8 param_1,undefined8 param_2)

{
  undefined auStack_8 [8];
  
  __libc_start_main(FUN_001014d4,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}
```

the entry will call function FUN_001014d4

```cpp

undefined8 FUN_001014d4(int param_1,long param_2)

{
  FILE *__stream;
  long lVar1;
  undefined8 *puVar2;
  undefined8 *puVar3;
  long in_FS_OFFSET;
  int local_f78;
  int local_f74;
  int local_f70;
  int local_f6c;
  int local_f58 [32];
  uint local_ed8 [32];
  uint local_e58 [32];
  char local_dd8 [16];
  char local_dc8 [16];
  char local_db8 [16];
  char acStack_da8 [32];
  undefined8 local_d88 [431];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_f58[0] = 0x17;
  local_f58[1] = 0x1a;
  local_f58[2] = 7;
  local_f58[3] = 3;
  local_f58[4] = 0x13;
  local_f58[5] = 1;
  local_f58[6] = 8;
  local_f58[7] = 0xe;
  local_f58[8] = 0x1b;
  local_f58[9] = 9;
  local_f58[10] = 0x1c;
  local_f58[11] = 0x14;
  local_f58[12] = 2;
  local_f58[13] = 0xf;
  local_f58[14] = 0x10;
  local_f58[15] = 0x11;
  local_f58[16] = 0x18;
  local_f58[17] = 5;
  local_f58[18] = 0x12;
  local_f58[19] = 0x19;
  local_f58[20] = 6;
  local_f58[21] = 0;
  local_f58[22] = 0x15;
  local_f58[23] = 0xd;
  local_f58[24] = 4;
  local_f58[25] = 0x16;
  local_f58[26] = 0x1f;
  local_f58[27] = 0x1e;
  local_f58[28] = 0xc;
  local_f58[29] = 0x1d;
  local_f58[30] = 0xb;
  local_f58[31] = 10;
  local_ed8[0] = 0xe7;
  local_ed8[1] = 0x7b;
  local_ed8[2] = 0x69;
  local_ed8[3] = 0xf;
  local_ed8[4] = 0x36;
  local_ed8[5] = 0x4b;
  local_ed8[6] = 1;
  local_ed8[7] = 0x4a;
  local_ed8[8] = 0xc1;
  local_ed8[9] = 0x19;
  local_ed8[10] = 0x38;
  local_ed8[11] = 0x4f;
  local_ed8[12] = 0x17;
  local_ed8[13] = 0xe9;
  local_ed8[14] = 0xa0;
  local_ed8[15] = 0x98;
  local_ed8[16] = 0xc4;
  local_ed8[17] = 0xff;
  local_ed8[18] = 0x40;
  local_ed8[19] = 0x7c;
  local_ed8[20] = 0x78;
  local_ed8[21] = 0x69;
  local_ed8[22] = 0x45;
  local_ed8[23] = 0x56;
  local_ed8[24] = 0x49;
  local_ed8[25] = 0x78;
  local_ed8[26] = 0x96;
  local_ed8[27] = 0x7c;
  local_ed8[28] = 0xfc;
  local_ed8[29] = 0xf9;
  local_ed8[30] = 0x4f;
  local_ed8[31] = 0x54;
  local_e58[0] = 0xd7;
  local_e58[1] = 0x1f;
  local_e58[2] = 0x5f;
  local_e58[3] = 0x6a;
  local_e58[4] = 0x54;
  local_e58[5] = 0x72;
  local_e58[6] = 0x32;
  local_e58[7] = 0x2b;
  local_e58[8] = 0xa0;
  local_e58[9] = 0x7a;
  local_e58[10] = 0x5d;
  local_e58[11] = 0x7c;
  local_e58[12] = 0x24;
  local_e58[13] = 0xde;
  local_e58[14] = 0xc4;
  local_e58[15] = 0xad;
  local_e58[16] = 0xf0;
  local_e58[17] = 0xcd;
  local_e58[18] = 0x23;
  local_e58[19] = 0x4b;
  local_e58[20] = 0x1b;
  local_e58[21] = 0x5f;
  local_e58[22] = 0x20;
  local_e58[23] = 99;
  local_e58[24] = 0x7f;
  local_e58[25] = 0x4f;
  local_e58[26] = 0xf7;
  local_e58[27] = 0x19;
  local_e58[28] = 0xc9;
  local_e58[29] = 0x98;
  local_e58[30] = 0x2c;
  local_e58[31] = 0x36;
  local_f78 = 0;
  puVar2 = &DAT_001020c8;
  puVar3 = local_d88;
  for (lVar1 = 0x1ae; lVar1 != 0; lVar1 = lVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  if (param_1 < 2) {
    puts("Usage: ./binary <passphrase>");
  }
  else {
    strncpy(local_db8,*(char **)(param_2 + 8),0x21);
    for (local_f74 = 0; local_f74 < 0x20; local_f74 = local_f74 + 1) {
      if (((int)local_db8[local_f58[local_f74]] ^ local_ed8[local_f74]) == local_e58[local_f74]) {
        local_f78 = local_f78 + 1;
      }
    }
    if (local_f78 == 0x20) {
      for (local_f70 = 0x10; local_f70 < 0x20; local_f70 = local_f70 + 1) {
        local_dd8[local_f70 + -0x10] = local_db8[local_f70];
      }
      for (local_f6c = 0; local_f6c < 0x10; local_f6c = local_f6c + 1) {
        local_dc8[local_f6c] = local_db8[local_f6c];
      }
      puts("Passhprase correct!");
      puts("Private will be written on private.pem!");
      FUN_001013be(local_d88,0xd70,local_dd8,local_dc8,0x10);
      __stream = fopen("/var/www/html/storage/jwt/private.pem","w");
      fprintf(__stream,(char *)local_d88);
      fclose(__stream);
    }
    else {
      puts("Passhprase incorrect!");
    }
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

```
this lines responsible for passphrase checker
```cpp
for (local_f74 = 0; local_f74 < 0x20; local_f74 = local_f74 + 1) {
      if (((int)local_db8[local_f58[local_f74]] ^ local_ed8[local_f74]) == local_e58[local_f74]) {
        local_f78 = local_f78 + 1;
      }
    }
```
```cpp
for (local_f74 = 0; local_f74 < 0x20; local_f74 = local_f74 + 1)
```
This is a for loop that initializes a variable local_f74 to 0 and iterates as long as local_f74 is less than 0x20 (32 in decimal). In each iteration, local_f74 is incremented by 1 (local_f74 = local_f74 + 1).

```cpp
if (((int)local_db8[local_f58[local_f74]] ^ local_ed8[local_f74]) == local_e58[local_f74])
```
- local_f58[local_f74]: Accesses an element in the array local_f58 at index local_f74.
- local_db8[local_f58[local_f74]]: Uses the value obtained from local_f58[local_f74] as an index to access an element in the array local_db8.
- (int)local_db8[local_f58[local_f74]]: Casts the value obtained from local_db8[local_f58[local_f74]] to an integer.
- local_ed8[local_f74]: Accesses an element in the array local_ed8 at index local_f74.
- ((int)local_db8[local_f58[local_f74]] ^ local_ed8[local_f74]): Performs a bitwise XOR (^) operation between the integer casted value and the element in local_ed8 array.

Finally, this result is compared to local_e58[local_f74].

the loop iterates through the indices from 0 to 31, performs some bitwise XOR operation and comparison, and increments local_f78 if the condition is satisfied.

Lets simplify the code

- local_f78 = iteration
- local_db8 = input
- local_f58 = index
- local_ed8 = key
- local_e58 = signature

to obtain valid input we need pass the comparasion 

input[index[iteration]] xor by key[iteration] must be match with signature[iteration]

```
a⊕b=c: XORing 'a' and 'b' results in 'c'.
c⊕b=a: XORing 'c' and 'b' (which is the result from the first operation) gives back 'a'.
a⊕c=b: XORing 'a' and 'c' (the original inputs) produces 'b'.
```

This set of relationships shows that if you XOR two values and then XOR the result with one of the original values, you get the other original value. It's a property of the XOR operation, and it's often used in computer science and cryptography.

This property is related to the fact that XOR is its own inverse. If you XOR a value with another and then XOR the result with the second value, you get back the first value. This is sometimes referred to as "cancellation" in the context of XOR operations.

therefore
```
signature[iteration] xor by key[iteration] will result in input[index[iteration]]
```
### SOLUTION

#### Passphrase generator
```py
index = [0x17, 0x1a, 7, 3, 0x13, 1, 8, 0xe, 0x1b, 9, 0x1c, 0x14, 2, 0xf, 0x10, 0x11,
             0x18, 5, 0x12, 0x19, 6, 0, 0x15, 0xd, 4, 0x16, 0x1f, 0x1e, 0xc, 0x1d, 0xb, 10]

key = [0xe7, 0x7b, 0x69, 0xf, 0x36, 0x4b, 1, 0x4a, 0xc1, 0x19, 0x38, 0x4f, 0x17, 0xe9,
             0xa0, 0x98, 0xc4, 0xff, 0x40, 0x7c, 0x78, 0x69, 0x45, 0x56, 0x49, 0x78, 0x96, 0x7c,
             0xfc, 0xf9, 0x4f, 0x54]

signature = [0xd7, 0x1f, 0x5f, 0x6a, 0x54, 0x72, 0x32, 0x2b, 0xa0, 0x7a, 0x5d, 0x7c, 0x24, 0xde,
             0xc4, 0xad, 0xf0, 0xcd, 0x23, 0x4b, 0x1b, 0x5f, 0x20, 99, 0x7f, 0x4f, 0xf7, 0x19,
             0xc9, 0x98, 0x2c, 0x36]

valid = [a ^ b for a, b in zip(key, signature)]
passphrase = [0] * 32

for x in range(0x20):
    passphrase[index[x]] = valid[x]

result_string = ''.join([chr(x) for x in passphrase])
print(result_string)

```
passphrase= 693e62c63cbc55a7d5cb3e7047daeaea

now we can set env JWT_PASSPHRASE=693e62c63cbc55a7d5cb3e7047daeaea

then run the project and trigger GET / to create the private key
after obtaining the private key we can craft JWT Token
refers to this [Writeup](/Protergo-24/web/Just-Wiggle-Tools/solution.md)

flag: **PROTERGO{673311e2d939238eaa08e461b0f4be5928293e26ac16ada1b5dbfed335c544b7}**