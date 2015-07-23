<?php

class wsAuth
{
  private $key = "wsAuth";
  private $aToken = array();

  private static $_instance;

  private function __construct () {}

  private function __clone () {}

  public static function getInstance () {
    if (!(self::$_instance instanceof self))
      self::$_instance = new self();

    return self::$_instance;
  }

  public function APIlogin($sUser, $sPassword)
  {
    if($sUser == '' || $sPassword == '')
    {
      throw new Exception('Bad arguments', 7);
    }

    $oSite = accessSite::verifyLogin($sUser);

    if(! $oSite instanceof Site)
    {
      throw new Exception('unknown user', 1);
    }

    if(!$oSite->isValidPassword($sPassword))
    {
      throw new Exception('wrong password', 2);
    }

    $aToken = array(
        "iss" => sfContext::getInstance()->getRequest()->getHost(),
        "aud" => $oSite->getIdSite());

    return $this->getToken($aToken);
  }

  public function userLogin($sUser, $sPassword)
  {

    $oAccount = user::checkLoginPass($sUser, $sPassword);

    if($oAccount)
    {
      $this->aToken["qiduser"] = $oAccount->id_global_account;
    }
    else
    {
      $oAccount = user::checkLogin($sUser);

      if($oAccount)
      {
        throw new Exception('wrong password', 2);
      }
      else
      {
        throw new Exception('unknown user', 1);
      }
    }

    return $this->getToken($this->aToken);
  }

  private function getToken($aToken = null)
  {
    $aToken["exp"] = time()+(30*60);
    $aToken["iat"] = time();

    $this->aToken = $aToken;

    return JWT::encode($aToken, $this->key);
  }

  public function checkToken($sTokenEnc)
  {
    return JWT::decode($sTokenEnc, $this->key);
  }

  public function checkApiAuth($sToken)
  {
    $aToken = (array)$this->checkToken($sToken);

    if(isset($aToken["aud"]))
    {
      return array('sToken' => $this->getToken($aToken), 'aToken' => $aToken);
    }
    else
    {
      throw new Exception('Bad token');
    }
  }

  public function checkUserAuth($sToken)
  {
    if($sToken = $this->checkApiAuth($sToken))
    {
      return $sToken;
    }
    else
    {
      return false;
    }
  }

}