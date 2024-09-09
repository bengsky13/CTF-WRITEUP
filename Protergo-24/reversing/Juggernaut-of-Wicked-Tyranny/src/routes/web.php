<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\HomeController;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "web" middleware group. Make something great!
|
*/

// Route::get('/', function () {
//     return view('welcome');
// });

Route::get('/', [HomeController::class, 'dashboard'])->name('dashboard');
Route::get('/portal_login', [HomeController::class, 'index'])->name('index');
Route::get('/portal_register', [HomeController::class, 'register'])->name('register');
Route::get('/home', [HomeController::class, 'home'])->name('home');