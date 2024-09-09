<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

use Tymon\JWTAuth\Facades\JWTAuth; //use this library
use Tymon\JWTAuth\Token;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Illuminate\Session\TokenMismatchException;

class HomeController extends Controller
{
    public function index(Request $request)
    {
        return view('login');
    }


    public function dashboard()
    {
        if (file_exists("/var/www/html/storage/jwt/private.pem")){
            return view('dashboard');
        }
        else{
            print_r(shell_exec("/var/www/html/storage/jwt/chall " . env('JWT_PASSPHRASE', '')));
        }
    }

    public function home(Request $request)
    {
        $flag = "";
        $rawToken = $request->cookie('auth');
        
        if($rawToken == ""){
            return redirect("/");
        }
        
        $token = new Token($rawToken);
        
        try{
            $payload = JWTAuth::decode($token);
            if ($payload->get('is_admin') == 1){
                $flag = "PROTERGO{FLAG}";
            }
        }
        catch(\Exception $e){
            return redirect("/");
        }

        return view('home', ['flag' => $flag]);
        
    }

    public function register(Request $request)
    {
        return view('register');
        
    }
}
