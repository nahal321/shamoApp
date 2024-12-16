<?php

namespace App\Http\Controllers\API;

use App\helpers\ResponseFormatter;
use App\Http\Controllers\Controller;
use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Laravel\Fortify\Rules\Password;

class UserController extends Controller
{
    public function register(Request $request)
    {
        try {
            $request->validate([
                'name' => ['required', 'string', 'max:255'],
                'username' => ['required', 'string', 'max:255', 'unique:users'],
                'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
                'phone' => ['nullable', 'string', 'max:255'],
                'password' => ['required', 'string', new Password],
            ]);


            user::create([
                'name' => $request->name,
                'username' => $request->username,
                'email' => $request->email,
                'phone' => $request->phone,
                'password' => Hash::make($request->name),
            ]);

            $user = User::where('email', $request->email)->first();

            $tokenResult = $user->createToken('authToken')->plainTextToken;

            return ResponseFormatter::success([
                'access_token' => $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user
            ], 'User Registered');
        } catch (Exception $error) {
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $error
            ], 'Authentication Failed', 500);
        }
    }

    public function login(Request $request)
    {
        try {
            $request->validate([
                'email' => 'email|required',
                'password' => 'required'
            ]);

            $credencials = request(['email', 'password']);
            if(!Auth::attempt($credencials)) {
                return ResponseFormatter::error([
                    'message' => 'Unauthorized'
                ], 'Authentication Failed', 500);
            }

            $user = User::where('email', $request->email)->first();

            if(! Hash::check($request->password, $user->password, [])) {
                throw new \Exception('Invalid Credensials');
            }
            
            $tokenResult = $user->createToken('authToken')->plainTextToken;
            return ResponseFormatter::success([
                'access_token' => $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user
            ], 'Authenticated');
        } catch (Exception $error) {
            return ResponseFormatter::error([
                'message' => 'Something Went Wrong',
                'error' => $error,
            ], 'Authentication Failed', 500);
        }
    }

    public function fetch (Request $request)
    {
        return ResponseFormatter::success($request->user(), 'Data Profile User Berhasil Diambil');
    }

    public function updateProfile(Request $request)
    {
        try {
            // Validasi input dari request
            $request->validate([
                'name' => ['required', 'string', 'max:255'],
                'username' => ['required', 'string', 'max:255', 'unique:users,username,' . Auth::id()],
                'email' => ['required', 'string', 'email', 'max:255', 'unique:users,email,' . Auth::id()],
                'phone' => ['nullable', 'string', 'max:255'],
                'password' => ['nullable', 'string', new Password], // Jika password diubah, validasi berlaku
            ]);

            // Ambil data yang sudah tervalidasi
            $data = $request->only(['name', 'username', 'email', 'phone', 'password']);
            
            // Cek jika password diubah
            if ($request->has('password')) {
                $data['password'] = Hash::make($request->password); // Enkripsi password baru
            }

            // Ambil data user yang sedang login
            $user = Auth::user();

            // Update profil user dengan data yang sudah tervalidasi
            $user->update($data);

            // Kembalikan response sukses
            return ResponseFormatter::success($user, 'Profile Updated');
        } catch (Exception $error) {
            // Tangani error jika terjadi kesalahan
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $error
            ], 'Profile Update Failed', 500);
        }
    }

    public function logout (Request $request)
    {
        $token = $request->user()->currentAccessToken()->delete();
        return ResponseFormatter::success($token, 'Token Rivoked');
    }    

}


