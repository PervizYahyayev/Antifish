<?php include('server.php') ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title> Login </title>
    <link rel="stylesheet" href="login.css">
</head>
<body>
<div class="box">   
    <div class="form"> 
        <h2> Login </h2>
        <form method="post" action="login.php" >
            <?php include('errors.php'); ?>
            <div class="inputBox"> 
                <input type="text" name="username" required="required">
                <span> Username </span>
                <i></i>
            </div>

            <div class="inputBox">
                <input type="password" name="password" required="required">
                <span> Password </span>
                <i></i>
            </div>

            <div class="links">
                <a href="#"> Don't have an account?</a>
                <a href="register.php"> Register now ! </a>
            </div>
        	<input type="submit" value="Login" name="login_user">
		</form>
    </div>
</div>
</body>
</html>