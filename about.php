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
  <link rel="stylesheet" href="about.css">
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@48,400,0,0" />
  <title> AntiFish </title>
</head>

<body>
  <div class="nav-bar">
    <div class="nav-logo">
      <img src="/img/programlogo.png" alt="">
    </div>

    <div class="headwelcome">
      <pre style="font-size: 22px;"><strong><?php echo $_SESSION['username']; ?></strong>, do you know what phishing attacks are?</pre>
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

  <div class="about-body">
    <div class="about-container">
      <div class="main-info-card">
        <div class="card-content">
          <h5>What are phishing attacks do?</h5>
          <p>
            "Phishing" refers to the attempt to steal sensitive information,
            usually in the form of usernames, passwords, credit card numbers,
            bank account information, or other sensitive information, in order
            to use or sell the stolen information. Similar to how a fisherman
            uses bait to catch fish, the attacker lures the victim in to trick
            the victim by pretending to be an authoritative source with a
            tempting request.
          </p>
        </div>
        <span class="question"><a>?</a></span>
      </div>

      <div class="attacks-container">
        <span class="search"> <a>!</a> </span>
        <h5>Famous phishing attacks:</h5>
        <ul class="attacks-ul">
          <li>AOHell, the First Recorded Example</li>
          <li>The Nordea Bank Incident</li>
          <li>Operation Phish Phry</li>
          <li>RSA</li>
          <li>Dyre Phishing Scam</li>
          <li>The Sony Pictures Leak</li>
          <li>Facebook & Google</li>
          <li>2018 World Cup.</li>
        </ul>
      </div>
      <div class="protect-container">
        <h5>How can we protect ourselves from phishing attacks?</h5>
        <ol class="protect-ol">
          <li>Recognize the signs of phishing</li>
          <li>Don't respond to a phishing email</li>
          <li>Report suspicious messages to your email provider</li>
          <li>Avoid sharing personal information</li>
          <li>Use strong passwords</li>
          <li>Use a firewall</li>
          <li>Stay informed</li>
          <li>Block pop-ups</li>
        </ol>
        <img class="phishing-card" src="img/phishing_card.svg" />
      </div>
      <div class="example-container">
        <img src="img/phishing_mail.svg" class="phishing-mail">
        <h5>Websites that reveals the malicious sites:</h5>
        <ol class="example-ol">
          <li> https://www.blacklist.gov.az/</li>
          <li>
            https://archive.siasat.com/news/top-100-dangerous-websites-revealed-29507/
          </li>
          <li>https://www.maxmind.com/en/high-risk-ip-sample-list</li>
        </ol>
      </div>
    </div>
  </div>
</body>

</html>