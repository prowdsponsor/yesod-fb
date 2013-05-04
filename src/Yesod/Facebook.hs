{-# LANGUAGE OverloadedStrings, TypeFamilies #-}
module Yesod.Facebook
  ( -- * Running @FacebookT@ actions inside @HandlerT@
    YesodFacebook(..)
  , runYesodFbT
  , runNoAuthYesodFbT
  , getFbCredentials

    -- * Real-time update notifications
  , parseRealTimeUpdateNotifications
  , answerRealTimeUpdateChallenge

    -- * Requests
  , lookupRequestIds
  ) where

import Control.Applicative ((<$>))
import Crypto.Classes (constTimeEq)
import Data.ByteString.Char8 () -- IsString
import qualified Data.Aeson as A
import qualified Data.ByteString.Lazy.Char8 as L
import qualified Data.Conduit as C
import qualified Data.Conduit.List as CL
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Facebook as FB
import qualified Network.Wai as W
import qualified Network.HTTP.Conduit as HTTP
import qualified Yesod.Core as Y


-- | The 'YesodFacebook' class for foundation datatypes that
-- support running 'FB.FacebookT' actions.
class Y.Yesod site => YesodFacebook site where
  -- | The credentials of your app.
  fbCredentials :: site -> FB.Credentials

  -- | HTTP manager used for contacting Facebook (may be the same
  -- as the one used for @yesod-auth@).
  fbHttpManager :: site -> HTTP.Manager

  -- | Use Facebook's beta tier if @True@.  The default is @False@.
  fbUseBetaTier :: site -> Bool
  fbUseBetaTier _ = False


-- | Returns Facebook's 'FB.Credentials' from inside a
-- 'Y.HandlerT'.  Just a convenience wrapper around
-- 'fbCredentials'.
getFbCredentials :: (Y.MonadHandler m, Y.HandlerSite m ~ site, YesodFacebook site) =>
                    m FB.Credentials
getFbCredentials = fbCredentials <$> Y.getYesod


-- | Run a 'FacebookT' action inside a 'Y.GHandler' using your
-- credentials.
runYesodFbT ::
  (Y.MonadHandler m, Y.HandlerSite m ~ site, YesodFacebook site) =>
  FB.FacebookT FB.Auth m a -> m a
runYesodFbT act = do
  site <- Y.getYesod
  let creds   = fbCredentials site
      manager = fbHttpManager site
  (if fbUseBetaTier site
   then FB.beta_runFacebookT
   else FB.runFacebookT) creds manager act


-- | Run a 'FacebookT' action inside a 'Y.GHandler' without using
-- your credentials.  Usually you won't need to use this function
-- but it's provided for completeness' sake.
runNoAuthYesodFbT ::
  (Y.MonadHandler m, Y.HandlerSite m ~ site, YesodFacebook site) =>
  FB.FacebookT FB.NoAuth m a -> m a
runNoAuthYesodFbT act = do
  site <- Y.getYesod
  let manager = fbHttpManager site
  (if fbUseBetaTier site
   then FB.runNoAuthFacebookT
   else FB.beta_runNoAuthFacebookT) manager act


----------------------------------------------------------------------


-- | Same as 'getRealTimeUpdateNotifications' but does the
-- heavy-lifting for you.  Throws an exception whenever any step
-- fails (signature header not found, invalid signature, invalid
-- JSON).
parseRealTimeUpdateNotifications ::
  (Y.MonadHandler m, Y.HandlerSite m ~ site, YesodFacebook site, A.FromJSON a) =>
  m (FB.RealTimeUpdateNotification a)
parseRealTimeUpdateNotifications = do
  let myFail = fail . ("parseRealTimeUpdateNotifications: " ++)
  -- Get request's signature.
  waiReq <- Y.waiRequest
  case lookup "X-Hub-Signature" (W.requestHeaders waiReq) of
    Nothing  -> myFail "X-Hub-Signature not found."
    Just sig -> do
      uncheckedData <- L.fromChunks <$> (Y.rawRequestBody C.$$ CL.consume)
      mcheckedData <- runYesodFbT $ FB.verifyRealTimeUpdateNotifications sig uncheckedData
      case mcheckedData of
        Nothing -> myFail "Signature is invalid."
        Just checkedData ->
          case A.decode checkedData of
            Nothing  -> myFail "Could not decode data."
            Just ret -> return ret


-- | Answer Facebook's challenge if the 'FB.RealTimeUpdateToken'
-- matches.
--
-- Whenever you modify your subscriptions, Facebook will try to
-- contact your server with the 'FB.RealTimeUpdateToken' that you
-- gave on your call to 'FB.modifySubscription'.  This function
-- will correctly answer Facebook's challenge if the
-- 'FB.RealTimeUpdateToken' matches, otherwise it will return
-- 'Y.notFound'.
answerRealTimeUpdateChallenge ::
     Y.MonadHandler m =>
     FB.RealTimeUpdateToken
  -> m Y.RepPlain
answerRealTimeUpdateChallenge token = do
  mhubMode        <- Y.lookupGetParam "hub.mode"
  mhubChallenge   <- Y.lookupGetParam "hub.challenge"
  mhubVerifyToken <- Y.lookupGetParam "hub.verify_token"
  case (mhubMode, mhubChallenge, mhubVerifyToken) of
    -- FIXME: Is hub.mode always subscribe?  Facebook's docs say
    -- so, but I don't believe them =).
    (Just "subscribe", Just hubChallenge, Just hubVerifyToken)
      | TE.encodeUtf8 hubVerifyToken `constTimeEq` token ->
          return $ Y.RepPlain (Y.toContent hubChallenge)
    _ -> Y.notFound


----------------------------------------------------------------------


-- | Lookup and parse the @request_ids@ GET parameter
-- <http://developers.facebook.com/docs/requests/>.
lookupRequestIds :: Y.MonadHandler m => m (Maybe [FB.Id])
lookupRequestIds = (map FB.Id . T.splitOn ",") <$$> Y.lookupGetParam "request_ids"
  where (<$$>) = fmap . fmap
