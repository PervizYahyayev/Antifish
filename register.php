<?php include('server.php') ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title> Register </title>
    <link rel="stylesheet" href="register.css">
</head>
<body>
<div class="box">   
    <div class="form"> 
        <h2> Register </h2>
        <form method="post" action="register.php">
            <?php include('errors.php'); ?>
            <div class="inputBox"> 
                <input type="text" name="username" value="<?php echo $username; ?>" required="required">
                <span style="color: rgb(84, 219, 12);" >Username</span>
                <i></i>
            </div>
            
            <div class="inputBox"> 


                <input type="email" name="email" value="<?php echo $email; ?>" required="required">
                <span style="color: rgb(84, 219, 12);"> E-mail </span>


                <i></i>
            </div>

            <div class="inputBox">
                <input type="password"  name="password_1" required="required">
                <span style="color: rgb(84, 219, 12);">  New password </span>
                <i></i>
            </div>

            <div class="inputBox">
                <input type="password" name="password_2" required="required">
                <span style="color: rgb(84, 219, 12);">  Confirm password </span>
                <i></i>
            </div>

            <div class="links">
                <a href="#"> Already have an account ?</a>
                <a href="login.php"> Login now !</a>
            </div>
			<input type="submit" value="Register"  name="reg_user"> 
        </form>
    </div>
</div>

</body>
</html>