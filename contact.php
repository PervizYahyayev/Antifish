<?php
require_once("virustotal.php");

session_start();
if (!isset($_SESSION['username'])) {
  $_SESSION['msg'] = "You must log in first";
  header('location: login.php');
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

?>
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="shortuct icon" href="/img/programlogo.png">
  <link rel="stylesheet" href="contact.css">
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@48,400,0,0" />
  <script src="https://kit.fontawesome.com/b99e675b6e.js"></script>
  <title> AntiFish </title>
</head>

<body>
  <div class="nav-bar">
    <div class="nav-logo">
      <img src="/img/programlogo.png" alt="">
    </div>

    <div class="headwelcome">
      <pre> Do you have a problem? Contact us <strong><?php echo $_SESSION['username']; ?></strong></pre>
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


  <div class="contact-page">



    <div class="wrapper1">
      <div class="left1">
        <img src="/img/tunal.jpg" alt="user" width="100">
        <h4> Həsənov Tünal </h4>
        <p> Backend Developer</p>
      </div>
      <div class="right1">
        <div class="info1">
          <h3>Information</h3>
          <div class="info_data1">
            <div class="data1">
              <h4>Email</h4>
              <p>tunalhsnov10@gmail.com</p>
            </div>
            <div class="data1">
              <h4>Phone</h4>
              <p>055-421-76-20</p>
            </div>
          </div>
        </div>

        <div class="projects1">
          <h3>Projects</h3>
          <div class="projects_data1">
            <div class="data1">
              <h4>Most Viewed</h4>
              <p> Backend </p>
            </div>
          </div>
        </div>

        <div class="social_media1">
          <ul>
            <li type="none"><a href="#"><i class="fab fa-facebook-f"></i></a></li>
            <li type="none"><a href="#"><i class="fab fa-twitter"></i></a></li>
            <li type="none"><a href="#"><i class="fab fa-instagram"></i></a></li>
          </ul>
        </div>
      </div>

    </div>


    <div class="wrapper2">
      <div class="left2">
        <img src="/img/samir.jpg" alt="user" width="100">
        <h4> Qasımlı Samir </h4>
        <p> Database and Frontend Developer</p>
      </div>
      <div class="right2">
        <div class="info2">
          <h3>Information</h3>
          <div class="info_data2">
            <div class="data2">
              <h4>Email</h4>
              <p>samirqasimli487@gmail.com</p>
            </div>
            <div class="data2">
              <h4>Phone</h4>
              <p>050-389-77-90</p>
            </div>
          </div>
        </div>

        <div class="projects2">
          <h3>Projects</h3>
          <div class="projects_data2">
            <div class="data2">
              <h4>Most Viewed</h4>
              <p>Database and Frontend</p>
            </div>
          </div>
        </div>

        <div class="social_media2">
          <ul>
            <li type="none"><a href="#"><i class="fab fa-facebook-f"></i></a></li>
            <li type="none"><a href="#"><i class="fab fa-twitter"></i></a></li>
            <li type="none"><a href="#"><i class="fab fa-instagram"></i></a></li>
          </ul>
        </div>
      </div>

      <div class="wrapper3">
        <div class="left3">
          <img src="/img/perviz.jpg" alt="user" width="100">
          <h4> Yahyayev Pərviz </h4>
          <p> Backend and Frontend Developer</p>
        </div>
        <div class="right3">
          <div class="info3">
            <h3>Information</h3>
            <div class="info_data3">
              <div class="data3">
                <h4>Email</h4>
                <p>pervizz992@gmail.com</p>
              </div>
              <div class="data3">
                <h4>Phone</h4>
                <p>099-898-05-55</p>
              </div>
            </div>
          </div>

          <div class="projects3">
            <h3>Projects</h3>
            <div class="projects_data3">
              <div class="data3">
                <h4>Most Viewed</h4>
                <p>Backend and Frontend</p>
              </div>

            </div>
          </div>

          <div class="social_media3">
            <ul>
              <li type="none"><a href="#"><i class="fab fa-facebook-f"></i></a></li>
              <li type="none"><a href="#"><i class="fab fa-twitter"></i></a></li>
              <li type="none"><a href="#"><i class="fab fa-instagram"></i></a></li>
            </ul>
          </div>
        </div>





        <div class="wrapper4">
          <div class="left4">
            <img src="/img/qarayev.jpeg" alt="user" width="100">
            <h4> Qarayev Məhəmməd </h4>
            <p> Backend Developer</p>
          </div>
          <div class="right4">
            <div class="info4">
              <h3>Information</h3>
              <div class="info_data4">
                <div class="data4">
                  <h4>Email</h4>
                  <p>muhammedqarayev777@gmail.com</p>
                </div>
                <div class="data4">
                  <h4>Phone</h4>
                  <p>055-977-52-18</p>
                </div>
              </div>
            </div>

            <div class="projects4">
              <h3>Projects</h3>
              <div class="projects_data4">
                <div class="data4">
                  <h4>Most Viewed</h4>
                  <p> Backend </p>
                </div>

              </div>
            </div>

            <div class="social_media4">
              <ul>
                <li type="none"><a href="#"><i class="fab fa-facebook-f"></i></a></li>
                <li type="none"><a href="#"><i class="fab fa-twitter"></i></a></li>
                <li type="none"><a href="#"><i class="fab fa-instagram"></i></a></li>
              </ul>
            </div>
          </div>
        </div>
      </div>



</body>

</html>