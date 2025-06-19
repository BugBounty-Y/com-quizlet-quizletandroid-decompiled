package com.amazon.device.ads;

import android.content.Context;
import android.text.TextUtils;
import android.view.View;
import android.webkit.WebView;
import androidx.camera.camera2.internal.RunnableC0130g;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3763y;

/* loaded from: classes.dex */
public class DtbOmSdkSessionManager {
    private static final String APS_OMSDK_ACTIVATION_NOT_INITIALIZED_MESSAGE = "OMIDSDK Activation failed to initialize";
    private static final String APS_OM_SDK_ACTIVATION_ERROR_MESSAGE = "OMIDSDK Failed to activate";
    private static final String APS_OM_SDK_ADD_FRIENDLY_OBSTRUCTION_ERROR_MESSAGE = "OMIDSDK Failed to add friendly obstruction";
    private static final String APS_OM_SDK_AD_EVENTS_CREATION_ERROR_MESSAGE = "OMIDSDK Failed to create ad event";
    private static final String APS_OM_SDK_AD_SESSION_CONFIG_ERROR_MESSAGE = "OMIDSDK Failed to initialize config for ";
    private static final String APS_OM_SDK_AD_SESSION_CREATION_ERROR_MESSAGE = "OMIDSDK Failed to create ad session";
    private static final String APS_OM_SDK_IMPRESSION_ERROR_MESSAGE = "OMIDSDK Failed to trigger impression event";
    private static final String APS_OM_SDK_LOAD_EVENT_ERROR_MESSAGE = "OMIDSDK Failed to load ad event";
    private static final String APS_OM_SDK_PARTNER_OBJECT_ERROR_MESSAGE = "OMIDSDK Failed to create partner object";
    private static final String APS_OM_SDK_REGISTER_AD_VIEW_ERROR_MESSAGE = "OMIDSDK Failed to register ad view";
    private static final String APS_OM_SDK_START_AD_SESSION_ERROR_MESSAGE = "OMIDSDK Failed to start ad session";
    private static final String APS_OM_SDK_STOP_AD_SESSION_ERROR_MESSAGE = "OMIDSDK Failed to stop ad session";
    private static final String LOGTAG = "DtbOmSdkSessionManager";
    private static boolean featureEnabled;
    private static boolean isOmSdkActive;
    private com.iab.omid.library.amazon.adsession.c adSessionConfiguration;
    private com.iab.omid.library.amazon.adsession.d adSessionContext;
    private com.iab.omid.library.amazon.adsession.a dtbOmSdkAdEvents;
    private com.iab.omid.library.amazon.adsession.b dtbOmSdkAdSession;
    private com.iab.omid.library.amazon.adsession.j dtbOmSdkPartner;

    private DtbOmSdkSessionManager() {
        computeFeatureEnabledFlag();
        if (featureEnabled) {
            DtbThreadService.executeOnMainThread(new n(this, 1));
        }
    }

    public static void activateOMSDK(Context context) {
        DtbThreadService.executeOnMainThread(new l(context, 4));
    }

    private void computeFeatureEnabledFlag() {
        if (DTBMetricsConfiguration.getDeniedOmSdkVersionList("denied_version_list").isEmpty()) {
            featureEnabled = true;
        } else {
            featureEnabled = !r0.contains(DtbConstants.INTEGRATED_OM_VERSION.replaceAll("_", "."));
        }
    }

    private void createOmAdEvents() {
        com.iab.omid.library.amazon.adsession.b bVar = this.dtbOmSdkAdSession;
        if (bVar == null) {
            com.amazon.aps.shared.a.e(1, 2, "OMIDSDK Failed to create ad event on create Ad Event", null);
            return;
        }
        com.iab.omid.library.amazon.adsession.k kVar = (com.iab.omid.library.amazon.adsession.k) bVar;
        com.iab.omid.library.amazon.publisher.a aVar = kVar.e;
        if (aVar.c != null) {
            throw new IllegalStateException("AdEvents already exists for AdSession");
        }
        if (kVar.g) {
            throw new IllegalStateException("AdSession is finished");
        }
        com.iab.omid.library.amazon.adsession.a aVar2 = new com.iab.omid.library.amazon.adsession.a(kVar);
        aVar.c = aVar2;
        this.dtbOmSdkAdEvents = aVar2;
        DtbLog.info(LOGTAG, "OMSDK : Open measurement ad Event created");
    }

    private void createOmAdSession(com.iab.omid.library.amazon.adsession.c cVar, com.iab.omid.library.amazon.adsession.d dVar) {
        if (cVar == null || dVar == null) {
            com.amazon.aps.shared.a.e(1, 2, APS_OM_SDK_AD_SESSION_CREATION_ERROR_MESSAGE, null);
        } else {
            if (!com.iab.omid.library.amazon.a.a.b) {
                throw new IllegalStateException("Method called before OM SDK activation");
            }
            this.dtbOmSdkAdSession = new com.iab.omid.library.amazon.adsession.k(cVar, dVar);
            DtbLog.info(LOGTAG, "OMSDK : Open measurement ad Session Created");
        }
    }

    public static boolean getFeatureEnableFlag() {
        return featureEnabled;
    }

    public static DtbOmSdkSessionManager getNewInstance() {
        if (isOmSdkActive) {
            return new DtbOmSdkSessionManager();
        }
        com.amazon.aps.shared.a.e(1, 2, APS_OMSDK_ACTIVATION_NOT_INITIALIZED_MESSAGE, null);
        return null;
    }

    private void initOmAdSession(final WebView webView, final String str, final com.iab.omid.library.amazon.adsession.f fVar, final com.iab.omid.library.amazon.adsession.i iVar, final com.iab.omid.library.amazon.adsession.i iVar2, final boolean z) {
        if (featureEnabled) {
            DtbThreadService.executeOnMainThread(new Runnable() { // from class: com.amazon.device.ads.m
                @Override // java.lang.Runnable
                public final void run() {
                    this.a.lambda$initOmAdSession$2(fVar, iVar, iVar2, z, webView, str);
                }
            });
        } else {
            DtbLog.error(LOGTAG, "OM SDK Feature Turned Off");
        }
    }

    public static boolean isOmSdkActive() {
        return isOmSdkActive;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void lambda$activateOMSDK$1(Context context) {
        try {
            com.iab.omid.library.amazon.a.a(context);
            isOmSdkActive = com.iab.omid.library.amazon.a.a.b;
        } catch (Throwable th) {
            com.amazon.aps.shared.a.e(1, 1, APS_OM_SDK_ACTIVATION_ERROR_MESSAGE, th);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void lambda$addFriendlyObstruction$8(View view, com.iab.omid.library.amazon.adsession.g gVar) {
        com.iab.omid.library.amazon.adsession.b bVar = this.dtbOmSdkAdSession;
        if (bVar == null) {
            com.amazon.aps.shared.a.e(1, 2, "OMIDSDK Failed to create ad session on add Friendly Obstruction", null);
            return;
        }
        try {
            bVar.a(view, gVar);
        } catch (RuntimeException unused) {
            com.amazon.aps.shared.a.e(1, 1, APS_OM_SDK_ADD_FRIENDLY_OBSTRUCTION_ERROR_MESSAGE, null);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void lambda$displayAdEventLoaded$5() {
        com.iab.omid.library.amazon.adsession.a aVar = this.dtbOmSdkAdEvents;
        if (aVar == null) {
            com.amazon.aps.shared.a.e(1, 2, "OMIDSDK Failed to create ad event on adLoaded event", null);
            return;
        }
        try {
            aVar.b();
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, APS_OM_SDK_LOAD_EVENT_ERROR_MESSAGE, e);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void lambda$impressionOccured$6() {
        com.iab.omid.library.amazon.adsession.a aVar = this.dtbOmSdkAdEvents;
        if (aVar == null) {
            com.amazon.aps.shared.a.e(1, 2, "OMIDSDK Failed to create ad event on impressionOccured", null);
            return;
        }
        try {
            aVar.a();
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, APS_OM_SDK_IMPRESSION_ERROR_MESSAGE, e);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void lambda$initOmAdSession$2(com.iab.omid.library.amazon.adsession.f fVar, com.iab.omid.library.amazon.adsession.i iVar, com.iab.omid.library.amazon.adsession.i iVar2, boolean z, WebView webView, String str) {
        if (this.dtbOmSdkPartner == null) {
            com.amazon.aps.shared.a.e(1, 2, APS_OM_SDK_PARTNER_OBJECT_ERROR_MESSAGE, null);
            return;
        }
        try {
            this.adSessionConfiguration = com.iab.omid.library.amazon.adsession.c.a(fVar, iVar, iVar2, z);
            com.iab.omid.library.amazon.adsession.j jVar = this.dtbOmSdkPartner;
            AbstractC3763y.a(jVar, "Partner is null");
            AbstractC3763y.a(webView, "WebView is null");
            com.iab.omid.library.amazon.adsession.d dVar = new com.iab.omid.library.amazon.adsession.d(jVar, webView, str);
            this.adSessionContext = dVar;
            createOmAdSession(this.adSessionConfiguration, dVar);
            if (com.iab.omid.library.amazon.adsession.f.HTML_DISPLAY.equals(fVar)) {
                createOmAdEvents();
            }
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, APS_OM_SDK_AD_SESSION_CONFIG_ERROR_MESSAGE + fVar, e);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void lambda$new$0() {
        try {
            String clientConfigVal = DTBMetricsConfiguration.getClientConfigVal("partner_name", "Amazon1", "om_sdk_feature");
            String sDKVersion = DtbCommonUtils.getSDKVersion();
            if (TextUtils.isEmpty(clientConfigVal)) {
                throw new IllegalArgumentException("Name is null or empty");
            }
            if (TextUtils.isEmpty(sDKVersion)) {
                throw new IllegalArgumentException("Version is null or empty");
            }
            this.dtbOmSdkPartner = new com.iab.omid.library.amazon.adsession.j(clientConfigVal, sDKVersion);
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(2, 1, APS_OM_SDK_PARTNER_OBJECT_ERROR_MESSAGE, e);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void lambda$registerAdView$3(WebView webView) {
        com.iab.omid.library.amazon.adsession.b bVar = this.dtbOmSdkAdSession;
        if (bVar == null) {
            com.amazon.aps.shared.a.e(1, 2, "OMIDSDK Failed to create ad session on register Ad View", null);
            return;
        }
        try {
            bVar.c(webView);
            DtbLog.info(LOGTAG, "OMSDK : Open measurement ad view registered");
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, APS_OM_SDK_REGISTER_AD_VIEW_ERROR_MESSAGE, e);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void lambda$startAdSession$4() {
        com.iab.omid.library.amazon.adsession.b bVar = this.dtbOmSdkAdSession;
        if (bVar == null) {
            com.amazon.aps.shared.a.e(1, 2, "OMIDSDK Failed to create ad session on start Ad Session", null);
            return;
        }
        try {
            bVar.d();
            DtbLog.info(LOGTAG, "OMSDK : Open measurement ad session id: " + ((com.iab.omid.library.amazon.adsession.k) this.dtbOmSdkAdSession).h);
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, APS_OM_SDK_START_AD_SESSION_ERROR_MESSAGE, e);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$stopOmAdSession$7() {
        com.iab.omid.library.amazon.adsession.b bVar = this.dtbOmSdkAdSession;
        if (bVar == null || !isOmSdkActive) {
            DtbLog.error(LOGTAG, "OMSDK : Open measurement ad Session not active");
            return;
        }
        try {
            bVar.b();
            this.adSessionContext = null;
            this.dtbOmSdkAdSession = null;
            this.dtbOmSdkAdEvents = null;
            this.adSessionConfiguration = null;
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, APS_OM_SDK_STOP_AD_SESSION_ERROR_MESSAGE, e);
        }
    }

    public void addFriendlyObstruction(View view, com.iab.omid.library.amazon.adsession.g gVar) {
        DtbThreadService.executeOnMainThread(new RunnableC0130g(this, view, gVar, 20));
    }

    public void displayAdEventLoaded() {
        DtbThreadService.executeOnMainThread(new n(this, 0));
    }

    public com.iab.omid.library.amazon.adsession.a getCurrentAdEvents() {
        return this.dtbOmSdkAdEvents;
    }

    public com.iab.omid.library.amazon.adsession.b getCurrentAdSession() {
        return this.dtbOmSdkAdSession;
    }

    public void impressionOccured() {
        DtbThreadService.executeOnMainThread(new n(this, 4));
    }

    public void initHtmlDisplayOmAdSession(WebView webView, String str) {
        initOmAdSession(webView, str, com.iab.omid.library.amazon.adsession.f.HTML_DISPLAY, com.iab.omid.library.amazon.adsession.i.NATIVE, com.iab.omid.library.amazon.adsession.i.NONE, false);
    }

    public void initJavaScriptOmAdSession(WebView webView, String str) {
        com.iab.omid.library.amazon.adsession.f fVar = com.iab.omid.library.amazon.adsession.f.DEFINED_BY_JAVASCRIPT;
        com.iab.omid.library.amazon.adsession.i iVar = com.iab.omid.library.amazon.adsession.i.JAVASCRIPT;
        initOmAdSession(webView, str, fVar, iVar, iVar, true);
    }

    public void registerAdView(WebView webView) {
        DtbThreadService.executeOnMainThread(new k(5, this, webView));
    }

    public void startAdSession() {
        DtbThreadService.executeOnMainThread(new n(this, 2));
    }

    public synchronized void stopOmAdSession() {
        DtbThreadService.executeOnMainThread(new n(this, 3));
    }
}
