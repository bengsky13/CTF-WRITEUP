<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Illuminate\Notifications\Notifiable;


class Login extends Authenticatable implements JWTSubject
{
    use HasFactory;
    use Notifiable;

    public function getJWTIdentifier()
    {
        return $this->getKey();
    }


    public function getJWTCustomClaims()
    {
        return [
            "is_admin" => $this->is_admin
        ];
    }

    protected $fillable = [
        'username',
        'password',
        'is_admin',
    ];
}
