package com.amazon.device.ads;

import android.app.Activity;
import android.os.Handler;
import android.os.Looper;
import java.util.Map;
import org.json.JSONException;

/* loaded from: classes.dex */
public class DTBAdMRAIDInterstitialController extends DTBAdMRAIDController implements DTBAdViewDisplayListener {
    private String bidId;
    DTBAdInterstitialListener interstitialListener;
    boolean pageDisplayed;
    boolean pageLoaded;

    public DTBAdMRAIDInterstitialController(DTBAdView dTBAdView, DTBAdInterstitialListener dTBAdInterstitialListener) {
        super(dTBAdView);
        this.pageLoaded = false;
        this.pageDisplayed = false;
        this.interstitialListener = dTBAdInterstitialListener;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: cleanOnCloseHandler, reason: merged with bridge method [inline-methods] */
    public void lambda$executeClose$0() {
        try {
            DTBAdView dTBAdView = this.adView;
            if (dTBAdView != null) {
                dTBAdView.setWebViewClient(null);
                this.adView.removeAllViews();
                this.adView.cleanup();
                DTBAdInterstitialListener dTBAdInterstitialListener = this.interstitialListener;
                if (dTBAdInterstitialListener != null) {
                    dTBAdInterstitialListener.onAdClosed(this.adView);
                }
            }
            Activity currentActivity = ActivityMonitor.getInstance().getCurrentActivity();
            if (this.useCustomClose && !currentActivity.isFinishing() && (currentActivity instanceof DTBInterstitialActivity)) {
                DTBInterstitialActivity dTBInterstitialActivity = (DTBInterstitialActivity) currentActivity;
                dTBInterstitialActivity.cleanup();
                dTBInterstitialActivity.finish();
            }
        } catch (RuntimeException e) {
            DtbLog.error(DTBAdMRAIDController.LOG_TAG, "Failed to execute cleanOnCloseHandler method");
            com.amazon.aps.shared.a.e(1, 2, "Failed to execute cleanOnCloseHandler method", e);
        }
    }

    private void executeClose(String str) {
        if (getDtbOmSdkSessionManager() != null) {
            getDtbOmSdkSessionManager().stopOmAdSession();
        }
        commandCompleted(str);
        setState(MraidStateType.HIDDEN);
        fireViewableChange(false);
        new Handler(Looper.getMainLooper()).post(new i(this, 7));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$impressionFired$6() {
        this.interstitialListener.onImpressionFired(this.adView);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$onAdClicked$1() {
        this.interstitialListener.onAdClicked(this.adView);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$onAdError$4() {
        this.interstitialListener.onAdError(this.adView);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$onAdFailedToLoad$3() {
        this.interstitialListener.onAdFailed(this.adView);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$onAdLeftApplication$5() {
        this.interstitialListener.onAdLeftApplication(this.adView);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$onAdLoaded$2() {
        this.interstitialListener.onAdLoaded(this.adView);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$onVideoCompleted$7() {
        this.interstitialListener.onVideoCompleted(this.adView);
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void expand(Map<String, Object> map) {
        fireErrorEvent("expand", "invalid placement type for interstitial ");
        commandCompleted("expand");
    }

    public DTBAdInterstitialListener getInterstitialListener() {
        return this.interstitialListener;
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public String getPlacementType() {
        return DTBAdSize.AAX_INTERSTITIAL_AD_SIZE;
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void impressionFired() {
        if (this.interstitialListener == null) {
            com.amazon.aps.shared.a.e(1, 2, "Failed to get interstitialListener on onAdError", null);
        } else {
            DtbThreadService.executeOnMainThread(new i(this, 4));
            super.impressionFired();
        }
    }

    public void initializeOnLoadAndDisplay() throws JSONException {
        if (this.pageLoaded && this.pageDisplayed) {
            prepareMraid();
        } else {
            createLoadReport();
        }
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController, com.amazon.device.ads.DTBActivityListener
    public void onActivityDestroyed(Activity activity) {
        if (getDtbOmSdkSessionManager() != null) {
            getDtbOmSdkSessionManager().stopOmAdSession();
        }
        ActivityMonitor.getInstance().setActivityListener(null);
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController, com.amazon.device.ads.DTBActivityListener
    public void onActivityResumed(Activity activity) {
        ActivityMonitor.getInstance().setActivityListener(null);
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void onAdClicked() {
        if (this.interstitialListener != null) {
            new Handler(Looper.getMainLooper()).post(new i(this, 1));
        }
    }

    public void onAdError() {
        if (this.interstitialListener == null) {
            com.amazon.aps.shared.a.e(1, 2, "Failed to get interstitialListener on onAdError", null);
        } else {
            DtbThreadService.executeOnMainThread(new i(this, 2));
        }
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void onAdFailedToLoad() {
        if (this.interstitialListener == null) {
            com.amazon.aps.shared.a.e(1, 2, "Failed to get interstitialListener on onAdFailedToLoad", null);
        } else {
            DtbThreadService.executeOnMainThread(new i(this, 0));
        }
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void onAdLeftApplication() {
        new Handler(Looper.getMainLooper()).post(new i(this, 5));
        ActivityMonitor.getInstance().setActivityListener(this);
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void onAdLoaded() {
        if (this.interstitialListener == null) {
            com.amazon.aps.shared.a.e(1, 2, "Failed to get interstitialListener on OnAdLoaded", null);
        } else {
            DtbThreadService.executeOnMainThread(new i(this, 3));
        }
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void onAdOpened() {
        DTBAdInterstitialListener dTBAdInterstitialListener = this.interstitialListener;
        if (dTBAdInterstitialListener != null) {
            dTBAdInterstitialListener.onAdOpen(this.adView);
        }
    }

    @Override // com.amazon.device.ads.DTBAdViewDisplayListener
    public void onInitialDisplay() {
        this.pageDisplayed = true;
        try {
            initializeOnLoadAndDisplay();
        } catch (JSONException e) {
            DtbLog.error("JSON exception:" + e.getMessage());
        }
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void onMRAIDClose() {
        executeClose("close");
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void onMRAIDUnload() {
        executeClose("unload");
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void onPageLoad() {
        this.pageLoaded = true;
        try {
            initializeOnLoadAndDisplay();
            if (DTBMetricsConfiguration.getInstance().isFeatureEnabled("additional_webview_metric", false)) {
                String bidId = getAdView().getBidId();
                this.bidId = bidId;
                com.amazon.aps.shared.a.c(null, "interstitialCreativeFinished", bidId);
            }
        } catch (JSONException e) {
            DtbLog.error("Error:" + e.getMessage());
        }
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void onResize(Map<String, Object> map) {
        fireErrorEvent("resize", "invalid placement type");
        commandCompleted("resize");
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void onVideoCompleted() {
        if (this.interstitialListener == null) {
            com.amazon.aps.shared.a.e(1, 2, "Failed to get interstitialListener on onAdError", null);
        } else {
            DtbThreadService.executeOnMainThread(new i(this, 6));
        }
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void passLoadError() {
        onAdError();
    }

    public void setInterstitialListener(DTBAdInterstitialListener dTBAdInterstitialListener) {
        this.interstitialListener = dTBAdInterstitialListener;
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void startEndCardDisplayOMSDKSession() {
        if (getDtbOmSdkSessionManager() == null || getAdView() == null) {
            com.amazon.aps.shared.a.e(2, 2, "OMSDK : Aps OMSDK Session Manager or AdView is null on start", null);
            return;
        }
        try {
            if (getDtbOmSdkSessionManager().getCurrentAdSession() != null) {
                getDtbOmSdkSessionManager().stopOmAdSession();
            }
            getDtbOmSdkSessionManager().initHtmlDisplayOmAdSession(getAdView(), "https://c.amazon-adsystem.com/");
            getDtbOmSdkSessionManager().registerAdView(getAdView());
            getDtbOmSdkSessionManager().startAdSession();
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, "OMSDK : End Card display : Unable to restart OM SDK session", e);
        }
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void startOMSDKSession() {
        if (getDtbOmSdkSessionManager() == null || getAdView() == null) {
            com.amazon.aps.shared.a.e(2, 2, "OMSDK : Aps OMSDK Session Manager or AdView is null on start", null);
            return;
        }
        try {
            if (getDtbOmSdkSessionManager().getCurrentAdSession() != null) {
                getDtbOmSdkSessionManager().stopOmAdSession();
            }
            if (getAdView().isVideo()) {
                getDtbOmSdkSessionManager().initJavaScriptOmAdSession(getAdView(), "https://c.amazon-adsystem.com/");
            } else {
                getDtbOmSdkSessionManager().initHtmlDisplayOmAdSession(getAdView(), "https://c.amazon-adsystem.com/");
            }
            getDtbOmSdkSessionManager().registerAdView(getAdView());
            getDtbOmSdkSessionManager().startAdSession();
            getDtbOmSdkSessionManager().displayAdEventLoaded();
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, "OMSDK :Unable to start OM SDK session", e);
        }
    }

    @Override // com.amazon.device.ads.DTBAdMRAIDController
    public void stopOMSDKSession() {
        if (getDtbOmSdkSessionManager() == null) {
            com.amazon.aps.shared.a.e(1, 2, "OMSDK : Aps OmSdk Session Manager is null on Stop Session", null);
        } else {
            getDtbOmSdkSessionManager().stopOmAdSession();
        }
    }
}
