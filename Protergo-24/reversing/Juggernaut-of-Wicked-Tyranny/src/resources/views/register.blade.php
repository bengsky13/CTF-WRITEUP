<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css">
    <title>Register</title>
</head>
<body>

<div class="container" style="margin-top: 50px">
    <div class="row">
        <div class="col-md-5 offset-md-3">
            <div class="card">
                <div class="card-body">
                    <label>REGISTER</label>
                    <hr>

                    <div class="form-group">
                        <label>Username</label>
                        <input type="text" class="form-control" id="username" placeholder="Masukkan username">
                    </div>

                    <div class="form-group">
                        <label>Password</label>
                        <input type="password" class="form-control" id="password" placeholder="Masukkan Password">
                    </div>

                    <div class="form-group">
                        <label>Confirm Password</label>
                        <input type="password" class="form-control" id="confirm-password" placeholder="Masukkan Password">
                    </div>

                    <button class="btn btn-register btn-block btn-success">REGISTER</button>


                </div>
            </div>

            <div class="text-center" style="margin-top: 15px">
                Sudah punya akun? <a href="/portal_login">Silahkan Login</a>
            </div>

        </div>
    </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script>
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/js/bootstrap.min.js" ></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/limonte-sweetalert2/8.11.8/sweetalert2.all.min.js"></script>

<script>
    $(document).ready(function() {

        $(".btn-register").click( function() {

            var username = $("#username").val();
            var password = $("#password").val();
            var confirm_password = $("#confirm-password").val();

            if(username.length == "") {

                Swal.fire({
                    type: 'warning',
                    title: 'Oops...',
                    text: 'Username Wajib Diisi !'
                });

            } else if(password.length == "") {

                Swal.fire({
                    type: 'warning',
                    title: 'Oops...',
                    text: 'Password Wajib Diisi !'
                });

            } else {

                $.ajax({

                    url: "/api/portal_register",
                    type: "POST",
                    cache: false,
                    data: {
                        "username": username,
                        "password": password,
                        "confirm-password" :confirm_password,
                    },

                    success:function(response){

                        if (response.success) {

                            Swal.fire({
                                type: 'success',
                                title: 'Register Berhasil!',
                                text: 'silahkan login!'
                            });

                            $("#username").val('');
                            $("#password").val('');
                            $("#confirm-password").val('');

                        } else {

                            Swal.fire({
                                type: 'error',
                                title: 'Register Gagal!',
                                text: 'silahkan coba lagi!'
                            });

                        }

                        console.log(response);

                    },

                    error:function(response){
                        Swal.fire({
                            type: 'error',
                            title: 'Opps!',
                            text: 'server error!'
                        });
                    }

                })

            }

        });

    });
</script>

</body>
</html>