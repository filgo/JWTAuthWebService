<?php
abstract class wsAction extends sfAction
{
  protected $aToken = null;
  protected $sToken = null;

  /**
   * (non-PHPdoc)
   * @see sfAction::preExecute()
   */
  public function preExecute()
  {
    $this->getResponse()->setContentType('application/json');

    $owsAuth = wsAuth::getInstance();

    try
    {
      $oRequest = sfContext::getInstance()->getRequest();
      $this->aToken = $this->checkAPIAuth($oRequest);
    } catch (Exception $e)
    {
      $aError = array('code' => $e->getCode(), 'error' => $e->getMessage());

      $this->getResponse()->setContent(json_encode($aError));
      $this->getResponse()->setStatusCode(200);
      $this->getResponse()->sendHttpHeaders();
      $this->getResponse()->sendContent();

      throw new sfStopException();
    }

    parent::preExecute();
  }

  /**
   * (non-PHPdoc)
   * @see sfAction::postExecute()
   */
  public function postExecute()
  {
    if($this->sToken)
    {
      $this->getResponse()->setHttpHeader('Token', $this->sToken);
    }

    parent::postExecute();
  }

  /**
   *
   * @param sfWebRequest $oRequest
   * @return Ambigous <array, string>
   */
  private function checkAPIAuth(sfWebRequest $oRequest)
  {
    $sToken = $oRequest->getHttpHeader('Token');

    $owsAuth = wsAuth::getInstance();
    $aResult = $owsAuth->checkApiAuth($sToken);

    $sToken = $aResult['sToken'];

    if($sToken)
    {
      $this->getResponse()->setHttpHeader('Token', $sToken);
    }

    return $aResult['aToken'];
  }

  /**
   * Verify if user is authenticated, generate Exception if he isn't
   */
  protected function isAuthenticated()
  {
    if(!isset($this->aToken['qiduser']) || $this->aToken['qiduser']=='')
    {
      throw new Exception('not authenticated', 8);
    }
  }

  /**
   *
   * @param unknown $aToCheck
   * @throws Exception
   */
  protected function checkArguments($aToCheck)
  {
    $oRequest = $this->getRequest();

    foreach ($aToCheck as $sToCheck)
    {
      if($oRequest->getParameter($sToCheck) == '')
      {
        throw new Exception('bad arguments', 7);
      }
    }
  }

  /**
   *
   * @param Exception $Error
   * @return sfView::NONE
   */
  protected function renderError($Error)
  {
    $aError = array('code' => $Error->getCode() ,'error' => $Error->getMessage());

    $this->getResponse()->setContent(json_encode($aError));
    $this->getResponse()->setStatusCode(200);
    $this->getResponse()->sendHttpHeaders();
    $this->getResponse()->sendContent();

    throw new sfStopException();
  }
}