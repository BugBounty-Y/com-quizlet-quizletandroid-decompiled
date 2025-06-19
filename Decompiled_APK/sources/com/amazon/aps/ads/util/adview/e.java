package com.amazon.aps.ads.util.adview;

import android.content.Context;
import android.graphics.Rect;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.MotionEvent;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.webkit.ValueCallback;
import android.webkit.WebView;
import androidx.camera.camera2.internal.RunnableC0130g;
import androidx.compose.animation.d0;
import com.amazon.aps.shared.metrics.model.k;
import com.amazon.device.ads.DTBAdBannerListener;
import com.amazon.device.ads.DTBAdMRAIDBannerController;
import com.amazon.device.ads.DTBAdMRAIDController;
import com.amazon.device.ads.DTBAdView;
import com.amazon.device.ads.DTBExpectedSizeProvider;
import com.amazon.device.ads.DTBMetricsConfiguration;
import com.amazon.device.ads.DtbCommonUtils;
import com.amazon.device.ads.DtbOmSdkSessionManager;
import com.amazon.device.ads.WebResourceOptions;
import com.amazon.device.ads.WebResourceService;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3538u;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public class e extends b implements j, g {
    public static final /* synthetic */ int b = 0;

    @NotNull
    private final Context adViewContext;
    private final boolean localOnly;
    protected f webBridge;
    private i webClient;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(@NotNull Context context) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
        this.localOnly = WebResourceOptions.isLocalSourcesOnly();
        this.adViewContext = context;
    }

    public static void a(e this$0, String str, ValueCallback valueCallback) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        super.evaluateJavascript(str, valueCallback);
    }

    public static void b(e this$0, String url) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(url, "$url");
        try {
            super.loadUrl(url);
        } catch (Exception e) {
            String strK = Intrinsics.k(url, "WebView crash noticed during super.loadUrl method. URL:");
            Intrinsics.checkNotNullParameter(this$0, "<this>");
            com.amazon.aps.shared.a.e(1, 1, strK, e);
        }
    }

    public void cleanup() {
        try {
            removeJavascriptInterface("amzn_bridge");
            DtbOmSdkSessionManager omSdkManager = getOmSdkManager();
            if (omSdkManager != null) {
                omSdkManager.stopOmAdSession();
            }
            DTBAdMRAIDController mraidHandler = getMraidHandler();
            if (mraidHandler != null) {
                mraidHandler.cleanup();
            }
            setMraidHandler(null);
        } catch (RuntimeException e) {
            Intrinsics.checkNotNullParameter(this, "<this>");
            com.amazon.aps.shared.a.e(1, 1, "Error in ApsAdView cleanup", e);
        }
    }

    public boolean detectAdClick(MotionEvent motionEvent) {
        if (isVideo() || motionEvent == null) {
            return false;
        }
        int action = motionEvent.getAction();
        long jF = assistantMode.refactored.a.f();
        if (action != 0) {
            if (action == 1 && jF - this.timeClicked >= 1000) {
                if (jF - this.timePressed < 500) {
                    this.timeClicked = jF;
                    if (getMraidHandler() != null) {
                        DTBAdMRAIDController mraidHandler = getMraidHandler();
                        Intrinsics.d(mraidHandler);
                        mraidHandler.onAdClicked();
                    } else {
                        com.amazon.aps.shared.a.e(1, 2, "Null controller instance onAdClick callback", null);
                    }
                }
                jF = 0;
            } else {
                jF = this.timePressed;
            }
        }
        this.timePressed = jF;
        return false;
    }

    public void evaluateApsJavascript(String str, ValueCallback<String> valueCallback) {
        if (str == null) {
            return;
        }
        new Handler(Looper.getMainLooper()).post(new RunnableC0130g(this, str, valueCallback, 19));
    }

    public void fetchAd(String str, @NotNull Map<String, ? extends Object> extra) {
        Intrinsics.checkNotNullParameter(extra, "extra");
        com.onetrust.otpublishers.headless.Internal.Helper.h hVar = c.a;
        Intrinsics.checkNotNullParameter(this, "webView");
        try {
            Bundle bundleInitializeEmptyBundle = DtbCommonUtils.initializeEmptyBundle();
            if (extra != null) {
                for (Map.Entry<String, ? extends Object> entry : extra.entrySet()) {
                    String key = entry.getKey();
                    Object value = entry.getValue();
                    if (value instanceof String) {
                        bundleInitializeEmptyBundle.putString(key, (String) value);
                    } else if (value instanceof Boolean) {
                        bundleInitializeEmptyBundle.putBoolean(key, ((Boolean) value).booleanValue());
                    } else if (value instanceof Integer) {
                        bundleInitializeEmptyBundle.putInt(key, ((Number) value).intValue());
                    } else if (value instanceof Long) {
                        bundleInitializeEmptyBundle.putLong(key, ((Number) value).longValue());
                    }
                }
            }
            fetchAd(str, bundleInitializeEmptyBundle);
        } catch (RuntimeException e) {
            Intrinsics.checkNotNullParameter(hVar, "<this>");
            com.amazon.aps.shared.a.e(1, 1, "Fail to execute fetchAd method with map bundle", e);
        }
    }

    public final void fetchAdWithLocation(String str) {
        Context context = getContext();
        if (context == null) {
            return;
        }
        com.onetrust.otpublishers.headless.Internal.Helper.h hVar = c.a;
        boolean localOnly = getLocalOnly();
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(this, "webView");
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("<script>");
            sb.append(hVar.t(context, null));
            sb.append("</script>");
            hVar.u(context, localOnly, "aps-mraid", sb);
            sb.append("<script>");
            sb.append("window.location=\"");
            sb.append(str);
            sb.append("\";");
            sb.append("</script>");
            loadDataWithBaseURL("https://c.amazon-adsystem.com/", sb.toString(), "text/html", "UTF-8", null);
        } catch (RuntimeException e) {
            Intrinsics.checkNotNullParameter(hVar, "<this>");
            com.amazon.aps.shared.a.e(1, 1, "Fail to execute fetchAdWithLocation method", e);
        }
    }

    public final void getAdInfo(@NotNull String adhtml, @NotNull Bundle adInfoBundle) {
        Intrinsics.checkNotNullParameter(adhtml, "adhtml");
        Intrinsics.checkNotNullParameter(adInfoBundle, "adInfoBundle");
        com.onetrust.otpublishers.headless.Internal.Helper.h.s(adhtml, adInfoBundle);
    }

    @Override // com.amazon.aps.ads.util.adview.g
    @NotNull
    public Context getAdViewContext() {
        return this.adViewContext;
    }

    @Override // com.amazon.aps.ads.util.adview.j
    public DTBAdMRAIDController getApsMraidHandler() {
        return getMraidHandler();
    }

    public final boolean getLocalOnly() {
        return this.localOnly;
    }

    public final i getWebClient() {
        return this.webClient;
    }

    public void initWebView() {
        com.quizlet.shared.usecase.folderstudymaterials.a.n(this);
        i hVar = new h(this);
        setWebViewClient(hVar);
        setWebClient(hVar);
        setAdViewScrollEnabled(false);
        f fVar = new f(this);
        this.webBridge = fVar;
        addJavascriptInterface(fVar, "amzn_bridge");
        WebResourceService.init();
        initLayoutListeners();
        setOnTouchListener(new d(this, 0));
    }

    @Override // com.amazon.aps.ads.util.adview.g
    public boolean isTwoPartExpand() {
        if (getMraidHandler() == null) {
            return false;
        }
        DTBAdMRAIDController mraidHandler = getMraidHandler();
        if (mraidHandler != null) {
            return mraidHandler.isTwoPartExpand();
        }
        throw new NullPointerException("null cannot be cast to non-null type com.amazon.device.ads.DTBAdMRAIDController");
    }

    public final void loadLocalFile(@NotNull String filename, @NotNull StringBuilder sb) {
        Intrinsics.checkNotNullParameter(filename, "filename");
        Intrinsics.checkNotNullParameter(sb, "sb");
        com.onetrust.otpublishers.headless.Internal.Helper.h hVar = c.a;
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "context");
        hVar.u(context, this.localOnly, filename, sb);
    }

    @Override // android.webkit.WebView
    public void loadUrl(@NotNull String url) {
        Intrinsics.checkNotNullParameter(url, "url");
        try {
            i iVar = this.webClient;
            if (iVar == null) {
                return;
            }
            if (!iVar.a) {
                new Handler(Looper.getMainLooper()).post(new androidx.credentials.playservices.controllers.c(11, this, url));
                return;
            }
            String strK = Intrinsics.k(url, "WebView is corrupted. loadUrl method will not be executed. URL:");
            Intrinsics.checkNotNullParameter(this, "<this>");
            com.amazon.aps.shared.a.e(1, 2, strK, null);
        } catch (RuntimeException e) {
            Intrinsics.checkNotNullParameter(this, "<this>");
            com.amazon.aps.shared.a.e(1, 1, "Failed to execute loadUrl method", e);
        }
    }

    @Override // com.amazon.aps.ads.util.adview.g
    public void onAdLeftApplication() {
        DTBAdMRAIDController mraidHandler = getMraidHandler();
        if (mraidHandler == null) {
            return;
        }
        mraidHandler.onAdLeftApplication();
    }

    @Override // com.amazon.aps.ads.util.adview.b
    public void onAdOpened() {
        DTBAdMRAIDController mraidHandler = getMraidHandler();
        if (mraidHandler == null) {
            return;
        }
        mraidHandler.onAdOpened();
    }

    public final void onAdRemoved() {
        if (getMraidHandler() == null) {
            Intrinsics.checkNotNullParameter(this, "<this>");
            com.amazon.aps.shared.a.e(1, 2, "Null controller instance onAdRemoved", null);
        } else {
            DTBAdMRAIDController mraidHandler = getMraidHandler();
            Intrinsics.d(mraidHandler);
            mraidHandler.onAdRemoved();
        }
    }

    @Override // com.amazon.aps.ads.util.adview.g
    public void onCrash(@NotNull WebView webView, @NotNull StringBuilder errorInfo, @NotNull String errorDetail) {
        DtbOmSdkSessionManager omSdkManager;
        Intrinsics.checkNotNullParameter(webView, "webView");
        Intrinsics.checkNotNullParameter(errorInfo, "errorInfo");
        Intrinsics.checkNotNullParameter(errorDetail, "errorDetail");
        try {
            if (webView instanceof DTBAdView) {
                String userAgentString = ((DTBAdView) webView).getSettings().getUserAgentString();
                if (userAgentString != null) {
                    String str = String.format("webViewUserAgentInfo = %s;", Arrays.copyOf(new Object[]{userAgentString}, 1));
                    Intrinsics.checkNotNullExpressionValue(str, "format(format, *args)");
                    errorInfo.append(str);
                }
                if (getBidId() != null) {
                    String str2 = String.format("webViewBidId = %s;", Arrays.copyOf(new Object[]{getBidId()}, 1));
                    Intrinsics.checkNotNullExpressionValue(str2, "format(format, *args)");
                    errorInfo.append(str2);
                }
                onAdRemoved();
                if (getMraidHandler() != null && (omSdkManager = getOmSdkManager()) != null) {
                    omSdkManager.stopOmAdSession();
                }
                ViewParent parent = ((DTBAdView) webView).getParent();
                if (parent != null && (parent instanceof ViewGroup)) {
                    ((ViewGroup) parent).removeView(this);
                }
                DTBAdMRAIDController mraidHandler = getMraidHandler();
                if (mraidHandler != null) {
                    mraidHandler.onLoadError();
                    cleanup();
                }
                webView.removeAllViews();
            }
            String strSubstring = errorDetail.substring(0, Math.min(100, errorDetail.length()));
            Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String…ing(startIndex, endIndex)");
            String str3 = String.format("webViewErrorDetail = %s", Arrays.copyOf(new Object[]{strSubstring}, 1));
            Intrinsics.checkNotNullExpressionValue(str3, "format(format, *args)");
            errorInfo.append(str3);
            String string = errorInfo.toString();
            Intrinsics.checkNotNullParameter(this, "<this>");
            com.amazon.aps.shared.a.e(1, 1, string, null);
        } catch (RuntimeException e) {
            String string2 = errorInfo.toString();
            Intrinsics.checkNotNullParameter(this, "<this>");
            com.amazon.aps.shared.a.e(1, 1, string2, e);
        }
    }

    @Override // com.amazon.aps.ads.util.adview.b
    public void onExposureChange(int i, @NotNull Rect adViewRect) {
        Intrinsics.checkNotNullParameter(adViewRect, "adViewRect");
        DTBAdMRAIDController mraidHandler = getMraidHandler();
        if (mraidHandler == null) {
            return;
        }
        mraidHandler.fireExposureChange(i, adViewRect);
    }

    @Override // com.amazon.aps.ads.util.adview.g
    public void onLoadError() {
        DTBAdMRAIDController mraidHandler = getMraidHandler();
        if (mraidHandler == null) {
            return;
        }
        mraidHandler.onLoadError();
    }

    @Override // com.amazon.aps.ads.util.adview.g
    public void onPageFinished(@NotNull String url, WebView webView) {
        DtbOmSdkSessionManager omSdkManager;
        Intrinsics.checkNotNullParameter(url, "url");
        try {
            AbstractC3538u.a(this, Intrinsics.k(url, "Page finished:"));
            if (webView instanceof DTBAdView) {
                if (StringsKt.G(url, "MRAID_ENV", false)) {
                    onPageLoaded();
                    return;
                }
                if (url.equals("https://c.amazon-adsystem.com/")) {
                    if ((getMraidHandler() instanceof DTBAdMRAIDBannerController) && (omSdkManager = getOmSdkManager()) != null) {
                        omSdkManager.stopOmAdSession();
                        if (isVideo()) {
                            omSdkManager.initJavaScriptOmAdSession(this, url);
                        } else {
                            omSdkManager.initHtmlDisplayOmAdSession(this, url);
                        }
                        omSdkManager.registerAdView(this);
                        omSdkManager.startAdSession();
                        if (!isVideo()) {
                            omSdkManager.displayAdEventLoaded();
                        }
                    }
                    onPageLoaded();
                }
            }
        } catch (RuntimeException e) {
            Intrinsics.checkNotNullParameter(this, "<this>");
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute onPageFinished method", e);
        }
    }

    public void onPageLoaded() {
        DTBAdMRAIDController mraidHandler = getMraidHandler();
        if (mraidHandler == null) {
            return;
        }
        mraidHandler.onPageLoad();
    }

    @Override // com.amazon.aps.ads.util.adview.b
    public void onPositionChanged(@NotNull Rect adViewRect) {
        Intrinsics.checkNotNullParameter(adViewRect, "adViewRect");
        DTBAdMRAIDController mraidHandler = getMraidHandler();
        if (mraidHandler == null) {
            return;
        }
        mraidHandler.onPositionChanged(adViewRect);
    }

    @Override // com.amazon.aps.ads.util.adview.b
    public void onViewabilityChanged(boolean z) {
        DTBAdMRAIDController mraidHandler = getMraidHandler();
        if (mraidHandler == null) {
            return;
        }
        mraidHandler.onViewabilityChanged(z);
    }

    @Override // com.amazon.aps.ads.util.adview.b
    public void setCurrentPositionProperty() {
        DTBAdMRAIDController mraidHandler = getMraidHandler();
        if (mraidHandler == null) {
            return;
        }
        mraidHandler.setCurrentPositionProperty();
    }

    public final void setIgnoreDetachment() {
        this.ignoreDetachment = true;
    }

    public final void setWebClient(i iVar) {
        if (iVar == null) {
            return;
        }
        this.webClient = iVar;
        setWebViewClient(iVar);
    }

    public void fetchAd(Map<String, ? extends Object> map) {
        if (map == null) {
            throw new NullPointerException("null cannot be cast to non-null type kotlin.collections.Map<kotlin.String?, kotlin.Any>");
        }
        fetchAd((String) null, map);
    }

    public void fetchAd(String str) {
        fetchAd(str, (Bundle) null);
    }

    public void fetchAd(Bundle bundle) {
        fetchAd((String) null, bundle);
    }

    public final void fetchAd(String str, Bundle bundle) {
        Bundle bundle2;
        long jCurrentTimeMillis = System.currentTimeMillis();
        if (D.l(str, null, false) || D.l(str, "", false)) {
            str = bundle == null ? null : bundle.getString("bid_html_template", null);
        }
        DTBAdMRAIDController mraidListener = getMraidHandler();
        if (mraidListener != null) {
            com.onetrust.otpublishers.headless.Internal.Helper.h hVar = c.a;
            Intrinsics.checkNotNullParameter(mraidListener, "mraidHandler");
            String string = (str != null || bundle == null) ? str : bundle.getString("bid_html_template", null);
            if (bundle != null && (mraidListener instanceof DTBAdMRAIDBannerController)) {
                DTBAdBannerListener dTBAdBannerListener = ((DTBAdMRAIDBannerController) mraidListener).bannerListener;
                int i = bundle.getInt("expected_width", 0);
                int i2 = bundle.getInt("expected_height", 0);
                if (i2 > 0 && i > 0 && (dTBAdBannerListener instanceof DTBExpectedSizeProvider)) {
                    DTBExpectedSizeProvider dTBExpectedSizeProvider = (DTBExpectedSizeProvider) dTBAdBannerListener;
                    dTBExpectedSizeProvider.setExpectedWidth(i);
                    dTBExpectedSizeProvider.setExpectedHeight(i2);
                }
            }
            if (DTBMetricsConfiguration.getInstance().isFeatureEnabled("webviewAdInfo_feature") && bundle == null) {
                bundle2 = new Bundle();
                com.onetrust.otpublishers.headless.Internal.Helper.h.s(string, bundle2);
                bundle2.putString("amazon_ad_info", d0.s(new Object[]{bundle2.getString("bid_identifier"), bundle2.getString("hostname_identifier"), bundle2.getString("event_server_parameter")}, 3, "{bidID:'%s',aaxHost:'%s',pricePoint:'%s'}", "format(format, *args)"));
            } else {
                bundle2 = bundle;
            }
            if (bundle2 != null) {
                setBidId(bundle2.getString("bid_identifier"));
                setHostname(bundle2.getString("hostname_identifier"));
                setVideo(bundle2.getBoolean("video_flag"));
            }
            setStartTime(new Date().getTime());
            Intrinsics.checkNotNullParameter(this, "webView");
            Intrinsics.checkNotNullParameter(mraidListener, "mraidListener");
            try {
                StringBuilder sb = new StringBuilder();
                sb.append("<!DOCTYPE html><html><head>");
                sb.append("<script>");
                sb.append(hVar.t(getAdViewContext(), bundle));
                sb.append("</script>");
                Context context = getContext();
                Intrinsics.checkNotNullExpressionValue(context, "webView.context");
                hVar.u(context, getLocalOnly(), "aps-mraid", sb);
                Context context2 = getContext();
                Intrinsics.checkNotNullExpressionValue(context2, "webView.context");
                hVar.u(context2, getLocalOnly(), "dtb-m", sb);
                if (DtbOmSdkSessionManager.getFeatureEnableFlag()) {
                    Context context3 = getContext();
                    Intrinsics.checkNotNullExpressionValue(context3, "webView.context");
                    hVar.u(context3, getLocalOnly(), "omsdk-v1", sb);
                }
                sb.append("</head>");
                sb.append("<body style='margin:0;padding:0;'>");
                sb.append(str);
                sb.append("</body></html>");
                if (DTBMetricsConfiguration.getInstance().isFeatureEnabled("additional_webview_metric", false)) {
                    if (mraidListener instanceof DTBAdMRAIDBannerController) {
                        com.amazon.aps.shared.a.c(null, "bannerCreativeRenderingStart", getBidId());
                    } else {
                        com.amazon.aps.shared.a.c(null, "interstitialCreativeRenderingStart", getBidId());
                    }
                }
                loadDataWithBaseURL("https://c.amazon-adsystem.com/", sb.toString(), "text/html", "UTF-8", null);
            } catch (RuntimeException e) {
                Intrinsics.checkNotNullParameter(hVar, "<this>");
                com.amazon.aps.shared.a.e(1, 1, "Fail to execute fetchAd method with bundle", e);
            }
        }
        String bidId = getBidId();
        com.airbnb.lottie.network.d dVar = new com.airbnb.lottie.network.d(17);
        dVar.r(getBidId());
        k kVar = (k) dVar.b;
        com.amazon.aps.shared.metrics.model.h hVar2 = kVar.h;
        if (hVar2 == null) {
            hVar2 = new com.amazon.aps.shared.metrics.model.h(null);
        }
        kVar.h = hVar2;
        hVar2.b = jCurrentTimeMillis;
        com.amazon.aps.shared.a.a(bidId, dVar);
    }
}
