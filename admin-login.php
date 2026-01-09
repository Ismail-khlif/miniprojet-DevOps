<?php
   session_start();
   error_reporting(1);
   include 'includes/config.php';
   if($_SESSION['alogin']!=''){
		$_SESSION['alogin']='';
   }
   if (empty($_SESSION['csrf_token_admin_login'])) {
       $_SESSION['csrf_token_admin_login'] = bin2hex(random_bytes(32));
   }
   if(isset($_POST['login']))
   {
	   if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token_admin_login'], $_POST['csrf_token'])) {
		   $_SESSION['msgErreur'] = "Votre session a expiré. Veuillez réessayer.";
	   } else {
		   $uname=$_POST['username'];
		   $password=md5($_POST['password']);
	   
		$sql = "SELECT UserName, Password, is_admin FROM users WHERE UserName = :username AND Password = :password";
		$query = $dbh->prepare($sql);
		$query->bindParam(':username', $uname, PDO::PARAM_STR);
		$query->bindParam(':password', $password, PDO::PARAM_STR);
		$query->execute();
		
		if ($query->rowCount() > 0) {
				$row = $query->fetch(PDO::FETCH_ASSOC);
				$_SESSION['alogin'] = $row['UserName'];
				$_SESSION['is_admin'] = $row['is_admin'];
				header('Location: dashboard.php');
				exit(); 
		}
	   else{
		   $_SESSION['msgErreur'] = "Mauvais identifiant / mot de passe.";
	   
	   }
   
   }
   
   ?>
<!DOCTYPE html>
<html lang="en">
   <head>
      <meta charset="utf-8">
      <meta http-equiv="X-UA-Compatible" content="IE=edge">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Login</title>
      <link rel="icon" type="image/x-icon" href="assets/images/favicon.png">
      <link rel="stylesheet" href="assets/css/bootstrap.min.css" media="screen" >
      <link rel="stylesheet" href="assets/css/font-awesome.min.css" media="screen" >
      <link rel="stylesheet" href="assets/css/animate-css/animate.min.css" media="screen" >
      <link rel="stylesheet" href="assets/css/prism/prism.css" media="screen" >

      <link rel="stylesheet" href="assets/css/main.css" media="screen" >
      <script src="assets/js/modernizr/modernizr.min.js"></script>
	  <style>
	  .error-message {
		  background-color: #fce4e4;
		  border: 1px solid #fcc2c3;
		  float: left;
		  padding: 0px 30px;
		  clear: both;
		}
	  </style>
   </head>
   <body class="" style="background-image: url(assets/images/back2.jpg);
      background-color: #ffffff;
      background-size: cover;
      height: 100%;


 
 
  /* Center and scale the image nicely */
  background-position: center;
  background-repeat: no-repeat;
  background-size: cover;">
  
      <div class="main-wrapper">
         <div class="">
            <div class="row">
               <div class="col-md-offset-7 col-lg-5">
                  <section class="section">
                     <div class="row mt-40">
                        <div class="col-md-offset-2 col-md-10  pt-50">
                           <div class="row mt-30 ">
                              <div class="col-md-11">
                                <div class="panel login-box" style="    background: #172541;">
                                    <div class="panel-heading">

                                       <div class="text-center"><br>
                                          <a href="#">
                    <img style="height: 70px" src="assets/images/footer-logo.png"></a>
                    <br>
                                          <h3 style="color: white;"> <strong>Login</strong></h3>
                                       </div>
                                    </div>
									<?php if (isset($_SESSION['msgErreur'])) { ?>
																	<p class="error-message"><?php echo $_SESSION['msgErreur']; unset($_SESSION['msgErreur']);?> </p><br><br>
									<?php } ?>
                                    <div class="panel-body p-20">
                                       <form class="admin-login" method="post">
                                          <input type="hidden" name="csrf_token" value="<?php echo htmlentities($_SESSION['csrf_token_admin_login']); ?>">
                                          <div class="form-group">
                                             <label for="inputUsername" class="control-label">Identifiant</label>
                                             <input type="text" name="username" class="form-control" id="inputUsername" placeholder="Identifiant">
                                          </div>
                                          <div class="form-group">
                                             <label for="inputPassword" class="control-label">Mot de passe</label>
                                             <input type="password" name="password" class="form-control" id="inputPassword" placeholder="Mot de passe">
                                          </div><br>
                                          <div class="form-group mt-20">
                                                <button type="submit" name="login" class="btn login-btn">Se Connecter</button>

                                          </div>
										                                         <div class="col-sm-6">
                                            <a href="index.php" class="text-white">Retour à l'accueil</a>
                                        </div>
                                          <br>
                                       </form>
                                    </div>
                                 </div>
                              </div>
                              <!-- /.col-md-11 -->
                           </div>
                           <!-- /.row -->
                        </div>
                        <!-- /.col-md-12 -->
                     </div>
                     <!-- /.row -->
                  </section>
               </div>
               <!-- /.col-md-6 -->
            </div>
            <!-- /.row -->
         </div>
         <!-- /. -->
      </div>
      <!-- /.main-wrapper -->
      <!-- ========== COMMON JS FILES ========== -->
      <script src="assets/js/jquery/jquery-2.2.4.min.js"></script>
      <script src="assets/js/jquery-ui/jquery-ui.min.js"></script>
      <script src="assets/js/bootstrap/bootstrap.min.js"></script>
      <script src="assets/js/pace/pace.min.js"></script>
      <script src="assets/js/lobipanel/lobipanel.min.js"></script>
      <script src="assets/js/iscroll/iscroll.js"></script>
      <!-- ========== PAGE JS FILES ========== -->
      <!-- ========== THEME JS ========== -->
      <script src="assets/js/main.js"></script>
      <script>
         $(function(){
         
         });
      </script>
 
   </body>
</html>
