<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;


use App\Models\Login;

use App\Http\Resources\LoginResource;

class RegisterController extends Controller
{
    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'username'     => 'required',
            'password'     => 'required',
            'confirm-password' => 'required|same:password'
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        $check = Login::where('username', $request->username)->count();
        if($check === 0){
            $data = $request->except('confirm-password', 'password');
            $data["is_admin"] = 0;
            $data['password'] = Hash::make($request->password);
            if (Login::create($data)){
                return new LoginResource(true, 'OK', []);
            }
        }
        return new LoginResource(false, 'OK', []);
    }
}
