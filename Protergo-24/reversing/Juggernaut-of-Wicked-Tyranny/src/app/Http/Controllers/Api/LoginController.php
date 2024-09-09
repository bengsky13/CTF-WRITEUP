<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Auth;

use App\Models\Login;

use App\Http\Resources\LoginResource;


class LoginController extends Controller
{
    public function index()
    {
        return new LoginResource(false, 'ERROR', []);
    }

    public function store(Request $request)
    {
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

    }

}
