<?php
require_once("virustotal.php");

session_start();
if (isset($_GET['logout'])) {
    session_destroy();
    unset($_SESSION['username']);
    header("location: login.php");
}
if (isset($_GET['logout'])) {
    session_destroy();
    unset($_SESSION['username']);
    header("location: login.php");
}

$API_KEY = '9be84f1aed6d157b7ebb6a3ee5cee7dea70abd1d5d6bdd9c98ed390aebf15fa3';

$virusTotal = new VirusTotal($API_KEY);

$url = "";
if (isset($_POST['url-input'])) {
    $url = $_POST['url-input'];
}

$ipAddress = "";
if (isset($_POST['ipAddress-input'])) {
    $ipAddress = $_POST['ipAddress-input'];
}


$file_path = "";

if ((isset($_FILES['my-file']) && $_FILES['my-file']['name'] != "")) {
    $target_dir = "file/";
    $file = $_FILES['my-file']['name'];
    $path = pathinfo($file);
    $filename = $path['filename'];
    $ext = $path['extension'];
    $temp_name = $_FILES['my-file']['tmp_name'];
    $path_filename_ext = $target_dir . $filename . "." . $ext;

    // Check if file already exists
    if (file_exists($path_filename_ext)) {
        $file_path = $path_filename_ext;
    } else {
        move_uploaded_file($temp_name, $path_filename_ext);
        $file_path = $path_filename_ext;
    }
}


?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="shortuct icon" href="/img/programlogo.png">
    <link rel="stylesheet" href="main.css">
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@48,400,0,0" />
    <title> AntiFish </title>
</head>

<body>
    <div class="nav-bar">
        <div class="nav-logo">
            <img src="/img/programlogo.png" alt="">
        </div>

        <div class="headwelcome">
            <pre> Welcome to AntiFish <strong><?php echo $_SESSION['username'] ?></strong></pre>
        </div>




        <div class="nav-main">
            <a href="/main.php"> Main </a>
        </div>

        <div class="nav-about">
            <a href="/about.php"> About </a>
        </div>

        <div class="nav-contact">
            <a href="/contact.php"> Contact </a>
        </div>

        <a href="main.php?logout='1'" class="reg-btn"> Log out </a>
    </div>

    <div class="main-page">
        <div class="cards-container">


            <form class="file-card" method="post" enctype="multipart/form-data">
                <div>
                    <p class="file-header"> FILE </p>
                </div>
                <div class="file-main"><span class="material-symbols-outlined">upload</span></div>
                <input type="file"  name="my-file"> <!-- class="file-btn" -->
                <div class="file-footer">
                    <p> 
                        By submitting data above, you are agreeing to our Terms of Service and Privacy Policy, and to the sharing of your Sample submission with the security community.
                    </p>
                </div>
                <input type="submit" name="submit-file" value="Click Result">
            </form>

            <form method="POST" class="url-card">
                <div class="url-header">URL</div>
                <div class="url-main"><span class="material-symbols-outlined">language</span> </div>
                <input type="text" id="url-input" name="url-input" placeholder="Search or scan a URL">
                <div class="url-footer">
                    <p>
                        By submitting data above, you are agreeing to our Terms of Service and Privacy Policy, and to the sharing of your URL submission with the security community.
                    </p>
                </div>
                <input type="submit" value="Click Result">
            </form>

            <form method="POST" class="search-card">
                <div class="search-header">IP Address</div>
                <div class="search-main"><span class="material-symbols-outlined">link</span></div>
                <input type="text" id="ipAddress-input" name="ipAddress-input" placeholder="Search or scan a IP Address">
                <div class="search-footer">
                    <p>
                        By submitting data above, you are agreeing to our Terms of Service and Privacy Policy, and to the sharing of your Sample submission with the security community.
                    </p>
                    <input type="submit" value="Click Result">
                </div>
            </form>


        </div>

        <div class="result-container">
            <div class="endresult">
                <p> RESULT </p>
            </div>
            <p class="content">
                <?php echo $virusTotal->getURLResult($url); ?>
                <?php echo $virusTotal->scanIpAddress($ipAddress); ?>
                <?php echo $virusTotal->printFileReport($file_path); ?>
            </p>
        </div>
    </div>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="app.js"></script>
</body>

</html>