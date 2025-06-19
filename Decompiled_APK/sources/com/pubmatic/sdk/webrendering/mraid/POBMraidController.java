package com.pubmatic.sdk.webrendering.mraid;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.content.MutableContextWrapper;
import android.graphics.Bitmap;
import android.graphics.Rect;
import android.os.Bundle;
import android.util.DisplayMetrics;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.webkit.ConsoleMessage;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.widget.FrameLayout;
import android.widget.ImageView;
import androidx.annotation.Keep;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.amazon.device.ads.DTBAdSize;
import com.amazon.device.ads.DtbDeviceDataRetriever;
import com.comscore.android.id.IdHelperAndroid;
import com.pubmatic.sdk.common.cache.a;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.webrendering.ui.POBFullScreenActivity;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import org.json.JSONException;
import org.json.JSONObject;

@Keep
/* loaded from: classes2.dex */
public class POBMraidController implements t, com.pubmatic.sdk.webrendering.ui.a {
    private static final String TAG = "POBMraidController";

    @NonNull
    private final Context appContext;
    private InterfaceC4072a audioVolumeChangeListener;

    @NonNull
    private POBMraidBridge currentBridge;
    private com.pubmatic.sdk.common.network.c imageNetworkListener;
    private int initialHeight;
    private int initialWidth;
    private boolean isAdVisible;
    private boolean isExposureChangeEnabled;
    private boolean isViewableChangeTracking;
    private com.pubmatic.sdk.common.utility.g locationDetector;

    @NonNull
    private final POBMraidBridge mraidBridge;
    private w mraidControllerListener;
    private boolean mraidInitState;
    private Map<String, String> orientationProperties;

    @NonNull
    private final String placementType;
    private com.pubmatic.sdk.common.network.g pobNetworkHandler;
    private final int rendererId;
    private C resizeView;
    private ViewTreeObserver.OnScrollChangedListener scrollChangeListener;
    private com.pubmatic.sdk.common.view.c twoPartWebView;
    private k twoPartWebViewTouchListener;
    private float visiblePercentage;
    private ViewGroup webViewParent;

    public class a implements com.pubmatic.sdk.common.network.c {
        public a() {
        }

        @Override // com.pubmatic.sdk.common.network.c
        public void onFailure(com.pubmatic.sdk.common.h hVar) {
            POBLog.error(POBMraidController.TAG, "Network error connecting to url.", new Object[0]);
            POBMraidController.this.destroyImageResource();
        }

        @Override // com.pubmatic.sdk.common.network.c
        public void onSuccess(Bitmap bitmap) {
            com.pubmatic.sdk.common.utility.o.runOnBackgroundThread(new u(this, bitmap));
            POBMraidController.this.destroyImageResource();
        }
    }

    public class b implements com.pubmatic.sdk.webrendering.mraid.g {
        public b() {
        }

        @Override // com.pubmatic.sdk.webrendering.mraid.g
        public void onDismiss() {
            POBMraidController.this.notifyAdCloseState();
        }

        @Override // com.pubmatic.sdk.webrendering.mraid.g
        public void onStart() {
            POBMraidController.this.notifyAdOpenState();
        }
    }

    public class c implements InterfaceC4072a {
        public c() {
        }

        @Override // com.pubmatic.sdk.webrendering.mraid.InterfaceC4072a
        public void a(Double d) {
            if (POBMraidController.this.adHasAudioFocus()) {
                POBMraidController.this.notifyAudioChangeToAd(d);
            } else {
                POBMraidController.this.notifyAudioChangeToAd(null);
            }
        }
    }

    public class d implements ViewTreeObserver.OnScrollChangedListener {
        public d() {
        }

        @Override // android.view.ViewTreeObserver.OnScrollChangedListener
        public void onScrollChanged() throws JSONException {
            POBMraidController.this.updateExposureProperty(true);
        }
    }

    public class e implements B {
        public e() {
        }

        @Override // com.pubmatic.sdk.webrendering.mraid.B
        public void a(WebView webView) throws JSONException {
            POBMraidController.this.handleResizeViewCloseEvent();
        }
    }

    public class f implements com.pubmatic.sdk.common.ui.d {
        final /* synthetic */ com.pubmatic.sdk.common.view.c a;
        final /* synthetic */ ViewGroup b;

        public f(com.pubmatic.sdk.common.view.c cVar, ViewGroup viewGroup) {
            this.a = cVar;
            this.b = viewGroup;
        }

        @Override // com.pubmatic.sdk.common.ui.d
        public void onCreate(@NonNull Activity activity) {
            this.a.setBaseContext(activity);
        }

        @Override // com.pubmatic.sdk.common.ui.d
        public void onDestroy() throws JSONException {
            POBLog.debug(POBMraidController.TAG, "expand close", new Object[0]);
            this.a.setBaseContext(POBMraidController.this.appContext);
            if (this.b != null) {
                FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(POBMraidController.this.initialWidth, POBMraidController.this.initialHeight);
                ViewGroup viewGroup = (ViewGroup) this.a.getParent();
                if (viewGroup != null) {
                    viewGroup.removeView(this.a);
                }
                this.b.addView(this.a, layoutParams);
                this.a.requestFocus();
            }
            POBMraidController.this.manageClose();
        }
    }

    public class g implements com.pubmatic.sdk.webrendering.ui.n {
        public g() {
        }

        @Override // com.pubmatic.sdk.webrendering.ui.n
        public void onClose() {
            POBFullScreenActivity.closeActivity(POBMraidController.this.appContext, POBMraidController.this.rendererId);
        }

        @Override // com.pubmatic.sdk.webrendering.ui.n
        public void onForward() {
        }
    }

    public class h implements com.pubmatic.sdk.webrendering.ui.k {
        public h() {
        }

        @Override // com.pubmatic.sdk.webrendering.ui.k
        public void onRenderProcessGone() {
            if (POBMraidController.this.twoPartWebView != null) {
                POBMraidController.this.twoPartWebView.destroy();
                POBMraidController.this.twoPartWebView = null;
            }
        }
    }

    public class i extends com.pubmatic.sdk.webrendering.mraid.f {
        final /* synthetic */ POBMraidBridge e;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public i(com.pubmatic.sdk.webrendering.ui.k kVar, POBMraidBridge pOBMraidBridge) {
            super(kVar);
            this.e = pOBMraidBridge;
        }

        @Override // com.pubmatic.sdk.webrendering.ui.l, android.webkit.WebViewClient
        public void onPageFinished(WebView webView, String str) throws JSONException {
            super.onPageFinished(webView, str);
            POBMraidController pOBMraidController = POBMraidController.this;
            pOBMraidController.initProperties(this.e, pOBMraidController.mraidInitState);
            POBMraidController.this.mraidInitState = false;
            if (POBMraidController.this.twoPartWebView != null) {
                POBMraidController.this.twoPartWebView.addOnLayoutChangeListener(new v(this));
                POBMraidController.this.mraidBridge.setMraidState(com.pubmatic.sdk.webrendering.mraid.j.EXPANDED);
                POBMraidController.this.currentBridge = this.e;
            }
        }
    }

    public static class j extends WebChromeClient {
        private j() {
        }

        @Override // android.webkit.WebChromeClient
        public boolean onConsoleMessage(ConsoleMessage consoleMessage) {
            POBLog.debug(POBMraidController.TAG, String.format(Locale.getDefault(), "%s @ %d: %s", consoleMessage.message(), Integer.valueOf(consoleMessage.lineNumber()), consoleMessage.sourceId()), new Object[0]);
            return super.onConsoleMessage(consoleMessage);
        }

        public /* synthetic */ j(a aVar) {
            this();
        }
    }

    public static class k implements View.OnTouchListener {
        boolean a;

        public boolean a() {
            boolean z = this.a;
            this.a = false;
            return z;
        }

        @Override // android.view.View.OnTouchListener
        @SuppressLint({"ClickableViewAccessibility"})
        public boolean onTouch(View view, MotionEvent motionEvent) {
            int action = motionEvent.getAction();
            if (action == 0 || action == 1) {
                POBLog.debug(POBMraidController.TAG, "WebView onTouch : Focus=" + view.hasFocus(), new Object[0]);
                if (view.hasFocus()) {
                    this.a = true;
                }
            }
            return false;
        }
    }

    public POBMraidController(@NonNull Context context, @NonNull POBMraidBridge pOBMraidBridge, @NonNull String str, int i2) {
        this.currentBridge = pOBMraidBridge;
        this.mraidBridge = pOBMraidBridge;
        this.rendererId = i2;
        this.placementType = str;
        pOBMraidBridge.setMraidBridgeListener(this);
        this.isAdVisible = this.currentBridge.webView.getVisibility() == 0;
        Context applicationContext = context.getApplicationContext();
        this.appContext = applicationContext;
        this.locationDetector = com.pubmatic.sdk.common.i.getLocationDetector(applicationContext);
        this.orientationProperties = new HashMap();
        this.isExposureChangeEnabled = false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean adHasAudioFocus() {
        return this.isAdVisible;
    }

    private void addAudioVolumeListener() {
        if (this.audioVolumeChangeListener == null) {
            this.audioVolumeChangeListener = new c();
        }
        C4073b.a().registerListener(this.appContext, this.audioVolumeChangeListener);
        updateRecentAudioVolumeToAd();
    }

    private void addExposureChangeListener() throws JSONException {
        if (this.scrollChangeListener == null) {
            this.scrollChangeListener = new d();
        }
        this.currentBridge.webView.getViewTreeObserver().addOnScrollChangedListener(this.scrollChangeListener);
        updateExposureProperty(true);
    }

    private void addToParent() {
        if (this.webViewParent != null) {
            this.webViewParent.addView(this.mraidBridge.webView, new FrameLayout.LayoutParams(this.initialWidth, this.initialHeight));
            this.webViewParent = null;
            this.mraidBridge.webView.requestFocus();
            this.initialWidth = 0;
            this.initialHeight = 0;
            w wVar = this.mraidControllerListener;
            if (wVar != null) {
                wVar.removeFriendlyObstructions(null);
                this.mraidControllerListener.onAdViewChanged(this.mraidBridge.webView);
            }
        }
    }

    private void allowOrientationChange(@NonNull Activity activity, boolean z) {
        if (z) {
            activity.setRequestedOrientation(-1);
        }
    }

    private void closeVideoPlayerActivity() {
        Intent intent = new Intent();
        intent.setAction(POBVideoPlayerActivity.ACTION_FINISH);
        this.appContext.sendBroadcast(intent);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void destroyImageResource() {
        com.pubmatic.sdk.common.network.g gVar = this.pobNetworkHandler;
        if (gVar != null) {
            gVar.cancelRequest(TAG);
            this.pobNetworkHandler = null;
        }
        this.imageNetworkListener = null;
    }

    private void dismissResize() {
        C c2 = this.resizeView;
        if (c2 != null) {
            c2.b();
        }
    }

    @SuppressLint({"SourceLockedOrientationActivity"})
    private void forceOrientation(@NonNull Activity activity, String str) {
        String str2 = str != null ? str : IdHelperAndroid.NO_ID_AVAILABLE;
        if (str2.equals(DtbDeviceDataRetriever.ORIENTATION_PORTRAIT)) {
            activity.setRequestedOrientation(1);
        } else if (str2.equals(DtbDeviceDataRetriever.ORIENTATION_LANDSCAPE)) {
            activity.setRequestedOrientation(0);
        } else {
            POBLog.debug(TAG, AbstractC0147y.d("default forceOrientation :", str), new Object[0]);
        }
    }

    private Double getAudioVolumePercentage(@NonNull Context context) {
        return C4073b.getAudioVolumePercentage(context);
    }

    private com.pubmatic.sdk.common.network.c getImageNetworkListener() {
        return new a();
    }

    private String getInterstitialOrientation(@NonNull Context context) {
        return com.pubmatic.sdk.common.utility.o.getDeviceOrientation(context) == 2 ? "sensor_landscape" : DtbDeviceDataRetriever.ORIENTATION_PORTRAIT;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void handleResizeViewCloseEvent() throws JSONException {
        addToParent();
        manageClose();
        this.resizeView = null;
    }

    @SuppressLint({"SetJavaScriptEnabled", "ClickableViewAccessibility"})
    private void handleTwoPartExpand(String str) {
        this.mraidInitState = true;
        com.pubmatic.sdk.common.view.c cVarCreateInstance = com.pubmatic.sdk.common.view.c.createInstance(this.appContext);
        this.twoPartWebView = cVarCreateInstance;
        if (cVarCreateInstance == null || com.pubmatic.sdk.common.utility.o.isNullOrEmpty(str)) {
            POBLog.error(TAG, "Unable to render two-part expand, as webview or URL is not available", new Object[0]);
            this.mraidBridge.notifyError("Unable to render two-part expand.", "expand");
            return;
        }
        this.twoPartWebView.getSettings().setJavaScriptEnabled(true);
        k kVar = new k();
        this.twoPartWebViewTouchListener = kVar;
        this.twoPartWebView.setOnTouchListener(kVar);
        addInlineVideoSupportToWebView(this.twoPartWebView);
        POBMraidBridge pOBMraidBridge = new POBMraidBridge(this.twoPartWebView);
        addCommandHandlers(pOBMraidBridge, true, false);
        pOBMraidBridge.setMraidBridgeListener(this);
        i iVar = new i(new h(), pOBMraidBridge);
        iVar.disableMultipleOnPageFinished(true);
        this.twoPartWebView.setWebViewClient(iVar);
        manageExpand(this.twoPartWebView, pOBMraidBridge);
        this.twoPartWebView.loadUrl(str);
    }

    private boolean isTwoPartExpandShowing() {
        return this.currentBridge != this.mraidBridge;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void manageClose() throws JSONException {
        Map<String, String> map = this.orientationProperties;
        if (map != null) {
            map.clear();
        }
        this.mraidBridge.setMraidState(com.pubmatic.sdk.webrendering.mraid.j.DEFAULT);
        if (isTwoPartExpandShowing()) {
            initProperties(this.mraidBridge, false);
            this.mraidBridge.setMraidBridgeListener(this);
            addCommandHandlers(this.mraidBridge, false, false);
        }
        this.currentBridge = this.mraidBridge;
        notifyAdCloseState();
    }

    private void manageExpand(@NonNull com.pubmatic.sdk.common.view.c cVar, @NonNull POBMraidBridge pOBMraidBridge) {
        if (this.initialWidth == 0) {
            this.initialWidth = cVar.getWidth();
        }
        if (this.initialHeight == 0) {
            this.initialHeight = cVar.getHeight();
        }
        ViewGroup viewGroup = (ViewGroup) cVar.getParent();
        if (viewGroup != null) {
            viewGroup.removeView(cVar);
        }
        f fVar = new f(cVar, viewGroup);
        com.pubmatic.sdk.webrendering.ui.m mVar = new com.pubmatic.sdk.webrendering.ui.m(this.appContext, cVar, false);
        mVar.setMraidViewContainerListener(new g());
        com.pubmatic.sdk.common.i.getAdViewCacheService().storeAdView(Integer.valueOf(this.rendererId), new a.C0008a(mVar, fVar));
        Intent intent = new Intent();
        intent.putExtra(POBFullScreenActivity.RENDERER_IDENTIFIER, this.rendererId);
        Map<String, String> map = this.orientationProperties;
        if (map != null && !map.isEmpty()) {
            String str = this.orientationProperties.get("forceOrientation");
            if (str != null) {
                intent.putExtra(POBFullScreenActivity.REQUESTED_ORIENTATION, str.equals(DtbDeviceDataRetriever.ORIENTATION_LANDSCAPE) ? 2 : 1);
            }
            String str2 = this.orientationProperties.get("allowOrientationChange");
            if (str2 != null) {
                intent.putExtra(POBFullScreenActivity.ALLOW_ORIENTATION_CHANGE, Boolean.parseBoolean(str2));
            }
        }
        POBFullScreenActivity.startActivity(this.appContext, intent);
        C c2 = this.resizeView;
        if (c2 != null) {
            c2.a(false);
            this.resizeView.a();
        }
        if (this.mraidBridge.getMraidState() == com.pubmatic.sdk.webrendering.mraid.j.DEFAULT) {
            notifyAdOpenState();
        }
        pOBMraidBridge.setMraidState(com.pubmatic.sdk.webrendering.mraid.j.EXPANDED);
        w wVar = this.mraidControllerListener;
        if (wVar != null) {
            wVar.onAdViewChanged(cVar);
            this.mraidControllerListener.addFriendlyObstructions(mVar.getSkipBtn(), com.pubmatic.sdk.common.viewability.h.CLOSE_AD);
        }
    }

    private void manageResize(Context context, int i2, int i3, int i4, int i5, boolean z) throws JSONException {
        C c2;
        com.pubmatic.sdk.webrendering.mraid.j mraidState = this.mraidBridge.getMraidState();
        com.pubmatic.sdk.webrendering.mraid.j jVar = com.pubmatic.sdk.webrendering.mraid.j.DEFAULT;
        if (mraidState == jVar || this.mraidBridge.getMraidState() == com.pubmatic.sdk.webrendering.mraid.j.RESIZED) {
            int[] viewXYPosition = com.pubmatic.sdk.common.utility.o.getViewXYPosition(this.mraidBridge.webView);
            int i6 = viewXYPosition[0];
            int i7 = viewXYPosition[1];
            if (this.mraidBridge.getMraidState().equals(jVar)) {
                this.initialWidth = this.mraidBridge.webView.getWidth();
                this.initialHeight = this.mraidBridge.webView.getHeight();
            }
            com.pubmatic.sdk.webrendering.mraid.h resizeValues = C4074c.getResizeValues(i4, i5, i2, i3, z, new com.pubmatic.sdk.webrendering.mraid.h(i6, i7, i3, i2, false, null), com.pubmatic.sdk.common.utility.o.convertPixelToDp(context.getResources().getDrawable(com.pubmatic.sdk.common.k.pob_close_button).getIntrinsicWidth()), com.pubmatic.sdk.common.utility.o.convertPixelToDp(context.getResources().getDrawable(com.pubmatic.sdk.common.k.pob_close_button).getIntrinsicHeight()));
            if (!resizeValues.isStatus()) {
                this.mraidBridge.notifyError(resizeValues.b, "resize");
                return;
            }
            int i8 = resizeValues.getxPosition();
            int i9 = resizeValues.getyPosition();
            int width = resizeValues.getWidth();
            int height = resizeValues.getHeight();
            C c3 = this.resizeView;
            if (c3 == null) {
                ViewGroup viewGroup = (ViewGroup) this.mraidBridge.webView.getParent();
                this.webViewParent = viewGroup;
                if (viewGroup != null) {
                    viewGroup.removeView(this.mraidBridge.webView);
                    C c4 = new C(this.appContext);
                    this.resizeView = c4;
                    ImageView imageViewC = c4.c();
                    this.resizeView.a((ViewGroup) this.webViewParent.getRootView(), this.mraidBridge.webView, width, height, i8, i9, new e());
                    this.resizeView.d();
                    w wVar = this.mraidControllerListener;
                    if (wVar != null && imageViewC != null) {
                        wVar.addFriendlyObstructions(imageViewC, com.pubmatic.sdk.common.viewability.h.CLOSE_AD);
                    }
                } else {
                    POBLog.error(TAG, "Unable to resize as web view parent view is null", new Object[0]);
                }
            } else {
                c3.a(width, height, i8, i9);
            }
            if (this.mraidBridge.getMraidState() == jVar) {
                notifyAdOpenState();
            }
            this.mraidBridge.setMraidState(com.pubmatic.sdk.webrendering.mraid.j.RESIZED);
            initProperties(this.mraidBridge, false);
            this.currentBridge = this.mraidBridge;
        } else {
            POBLog.debug(TAG, "Ad is already open in " + this.mraidBridge.getMraidState().a() + " state!", new Object[0]);
            this.mraidBridge.notifyError("Ad is already open in " + this.mraidBridge.getMraidState().a() + " state!", "resize");
        }
        if (this.mraidControllerListener == null || (c2 = this.resizeView) == null || c2.c() == null) {
            return;
        }
        this.mraidControllerListener.addFriendlyObstructions(this.resizeView.c(), com.pubmatic.sdk.common.viewability.h.CLOSE_AD);
    }

    private void notifyAdClick() {
        w wVar = this.mraidControllerListener;
        if (wVar != null) {
            wVar.onMRAIDAdClick();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void notifyAdCloseState() {
        w wVar = this.mraidControllerListener;
        if (wVar != null) {
            wVar.onAdInteractionStopped();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void notifyAdOpenState() {
        w wVar = this.mraidControllerListener;
        if (wVar != null) {
            wVar.onAdInteractionStarted();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void notifyAudioChangeToAd(Double d2) {
        this.currentBridge.setAudioVolumePercentage(d2);
    }

    private void removeAudioVolumeListener() {
        if (this.audioVolumeChangeListener != null) {
            C4073b.a().unregisterListener(this.appContext, this.audioVolumeChangeListener);
        }
        this.audioVolumeChangeListener = null;
    }

    private void removeExposureChangeListener() {
        if (this.scrollChangeListener != null) {
            this.currentBridge.webView.getViewTreeObserver().removeOnScrollChangedListener(this.scrollChangeListener);
            this.scrollChangeListener = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateExposureProperty(boolean z) throws JSONException {
        float fWidth;
        JSONObject rectJson;
        if (z) {
            Rect rect = new Rect();
            this.currentBridge.webView.getGlobalVisibleRect(rect);
            fWidth = ((rect.width() * rect.height()) / (this.currentBridge.webView.getWidth() * this.currentBridge.webView.getHeight())) * 100.0f;
            rectJson = C4074c.getRectJson(com.pubmatic.sdk.common.utility.o.convertPixelToDp(rect.left), com.pubmatic.sdk.common.utility.o.convertPixelToDp(rect.top), com.pubmatic.sdk.common.utility.o.convertPixelToDp(rect.width()), com.pubmatic.sdk.common.utility.o.convertPixelToDp(rect.height()));
        } else {
            rectJson = C4074c.getRectJson(0, 0, 0, 0);
            fWidth = DefinitionKt.NO_Float_VALUE;
        }
        if (Math.abs(this.visiblePercentage - fWidth) > 1.0f) {
            this.visiblePercentage = fWidth;
            POBLog.debug(TAG, "visible percentage :" + fWidth, new Object[0]);
            this.currentBridge.updateExposureChangeData(Float.valueOf(this.visiblePercentage), rectJson);
        }
    }

    private void updateRecentAudioVolumeToAd() {
        if (adHasAudioFocus()) {
            notifyAudioChangeToAd(getAudioVolumePercentage(this.appContext));
        } else {
            notifyAudioChangeToAd(null);
        }
    }

    public void addCommandHandlers(@NonNull POBMraidBridge pOBMraidBridge, boolean z, boolean z2) {
        pOBMraidBridge.addCommandHandler(new p());
        if (!z2) {
            pOBMraidBridge.addCommandHandler(new m());
            pOBMraidBridge.addCommandHandler(new r());
            pOBMraidBridge.addCommandHandler(new D());
        }
        pOBMraidBridge.addCommandHandler(new s());
        pOBMraidBridge.addCommandHandler(new l());
        pOBMraidBridge.addCommandHandler(new x());
        pOBMraidBridge.addCommandHandler(new com.pubmatic.sdk.webrendering.mraid.k());
        if (z) {
            return;
        }
        pOBMraidBridge.addCommandHandler(new o());
        pOBMraidBridge.addCommandHandler(new q());
    }

    public void addInlineVideoSupportToWebView(@NonNull WebView webView) {
        webView.setWebChromeClient(new j(null));
        try {
            webView.getSettings().setMediaPlaybackRequiresUserGesture(false);
        } catch (NoSuchMethodError e2) {
            POBLog.error(TAG, "Not able to add inline video support to WebView, %s", e2.getLocalizedMessage());
        }
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.t
    public void close() {
        POBLog.debug(TAG, "Received MRAID close event", new Object[0]);
        if (!this.placementType.equals("inline")) {
            if (this.placementType.equals(DTBAdSize.AAX_INTERSTITIAL_AD_SIZE)) {
                notifyAdCloseState();
                return;
            }
            return;
        }
        int i2 = AbstractC4075d.a[this.currentBridge.getMraidState().ordinal()];
        if (i2 == 1) {
            POBFullScreenActivity.closeActivity(this.appContext, this.rendererId);
        } else {
            if (i2 != 2) {
                return;
            }
            dismissResize();
        }
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.t
    public void createCalendarEvent(JSONObject jSONObject, boolean z) {
        if (z) {
            notifyAdClick();
        }
        try {
            Map<String, Object> mapA = C4074c.a(new JSONObject(jSONObject.optString("event")));
            POBLog.debug(TAG, "calendarParams :%s", mapA.toString());
            Intent type = new Intent("android.intent.action.INSERT").setType("vnd.android.cursor.item/event");
            for (Map.Entry<String, Object> entry : mapA.entrySet()) {
                Object value = entry.getValue();
                String key = entry.getKey();
                if (value instanceof Long) {
                    type.putExtra(key, ((Long) value).longValue());
                } else if (value instanceof Integer) {
                    type.putExtra(key, ((Integer) value).intValue());
                } else {
                    type.putExtra(key, (String) value);
                }
            }
            type.setFlags(268435456);
            this.appContext.startActivity(type);
            w wVar = this.mraidControllerListener;
            if (wVar != null) {
                wVar.onLeavingApplication();
            }
        } catch (ActivityNotFoundException e2) {
            this.currentBridge.notifyError("Device does not have calendar app." + e2.getLocalizedMessage(), "createCalendarEvent");
            POBLog.error(TAG, "Device does not have calendar app.%s", e2.getLocalizedMessage());
        } catch (IllegalArgumentException e3) {
            this.currentBridge.notifyError("Error parsing calendar event data." + e3.getLocalizedMessage(), "createCalendarEvent");
            POBLog.error(TAG, "Error parsing calendar event data.%s", e3.getLocalizedMessage());
        } catch (Exception e4) {
            this.currentBridge.notifyError("Something went wrong." + e4.getLocalizedMessage(), "createCalendarEvent");
            POBLog.error(TAG, "Something went wrong.%s", e4.getLocalizedMessage());
        }
    }

    public void destroy() {
        removeAudioVolumeListener();
        removeExposureChangeListener();
        destroyImageResource();
        dismissResize();
        com.pubmatic.sdk.common.network.g gVar = this.pobNetworkHandler;
        if (gVar != null) {
            gVar.cancelRequest(TAG);
            this.pobNetworkHandler = null;
        }
        this.imageNetworkListener = null;
        closeVideoPlayerActivity();
        this.isViewableChangeTracking = false;
        if (this.mraidBridge.getMraidState() == com.pubmatic.sdk.webrendering.mraid.j.EXPANDED) {
            POBFullScreenActivity.closeActivity(this.appContext, this.rendererId);
        }
        this.locationDetector = null;
        this.orientationProperties = null;
        this.isExposureChangeEnabled = false;
        com.pubmatic.sdk.common.view.c cVar = this.twoPartWebView;
        if (cVar != null) {
            cVar.destroy();
            this.twoPartWebView = null;
        }
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.t
    public void expand(String str, boolean z) {
        if (!this.placementType.equals("inline")) {
            POBLog.error(TAG, "Can't expand interstitial ad.", new Object[0]);
            this.mraidBridge.notifyError("Can't expand interstitial ad.", "expand");
            return;
        }
        if (z) {
            notifyAdClick();
        }
        if (this.mraidBridge.getMraidState() == com.pubmatic.sdk.webrendering.mraid.j.DEFAULT || this.mraidBridge.getMraidState() == com.pubmatic.sdk.webrendering.mraid.j.RESIZED) {
            if (str != null && !str.isEmpty()) {
                handleTwoPartExpand(str);
            } else {
                POBMraidBridge pOBMraidBridge = this.mraidBridge;
                manageExpand(pOBMraidBridge.webView, pOBMraidBridge);
            }
        }
    }

    public void initProperties(@NonNull POBMraidBridge pOBMraidBridge, boolean z) throws JSONException {
        com.pubmatic.sdk.common.view.c cVar = pOBMraidBridge.webView;
        int i2 = com.pubmatic.sdk.common.utility.o.getViewXYPosition(cVar)[0];
        int i3 = com.pubmatic.sdk.common.utility.o.getViewXYPosition(cVar)[1];
        int iConvertPixelToDp = com.pubmatic.sdk.common.utility.o.convertPixelToDp(cVar.getWidth());
        int iConvertPixelToDp2 = com.pubmatic.sdk.common.utility.o.convertPixelToDp(cVar.getHeight());
        DisplayMetrics displayMetrics = this.appContext.getResources().getDisplayMetrics();
        int iConvertPixelToDp3 = com.pubmatic.sdk.common.utility.o.convertPixelToDp(displayMetrics.widthPixels);
        int iConvertPixelToDp4 = com.pubmatic.sdk.common.utility.o.convertPixelToDp(displayMetrics.heightPixels);
        if (z) {
            pOBMraidBridge.setScreenSize(iConvertPixelToDp3, iConvertPixelToDp4);
            pOBMraidBridge.setDefaultPosition(i2, i3, iConvertPixelToDp, iConvertPixelToDp2);
            pOBMraidBridge.setPlacementType(this.placementType);
            boolean zA = C4074c.a(this.appContext);
            pOBMraidBridge.setSupportedFeatures(zA, zA, true, true, true, true, false);
            com.pubmatic.sdk.common.models.h location = com.pubmatic.sdk.common.utility.o.getLocation(this.locationDetector);
            if (location != null) {
                pOBMraidBridge.setLocation(location);
            }
            pOBMraidBridge.updateMraidState(pOBMraidBridge.getMraidState());
            pOBMraidBridge.updateEvent(com.pubmatic.sdk.webrendering.mraid.i.READY);
            pOBMraidBridge.updateViewable(true);
            iConvertPixelToDp4 = iConvertPixelToDp4;
        }
        boolean maxSize = pOBMraidBridge.setMaxSize(iConvertPixelToDp3, iConvertPixelToDp4);
        boolean currentPosition = pOBMraidBridge.setCurrentPosition(i2, i3, iConvertPixelToDp, iConvertPixelToDp2);
        if (maxSize || currentPosition) {
            pOBMraidBridge.setSizeChange(iConvertPixelToDp, iConvertPixelToDp2);
            if (this.isExposureChangeEnabled) {
                updateExposureProperty(cVar.isShown());
            }
        }
        pOBMraidBridge.updateMraidState(pOBMraidBridge.getMraidState());
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.t
    public boolean isUserInteracted(boolean z) {
        k kVar;
        if (isTwoPartExpandShowing() && (kVar = this.twoPartWebViewTouchListener) != null) {
            return kVar.a();
        }
        w wVar = this.mraidControllerListener;
        return wVar != null && wVar.isUserInteracted(z);
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.t
    public void listenerChanged(String str, boolean z) throws JSONException {
        if ("audioVolumeChange".equalsIgnoreCase(str)) {
            if (z) {
                addAudioVolumeListener();
                return;
            } else {
                removeAudioVolumeListener();
                return;
            }
        }
        if (!"exposureChange".equalsIgnoreCase(str)) {
            if ("viewableChange".equalsIgnoreCase(str)) {
                this.isViewableChangeTracking = z;
                return;
            } else {
                POBLog.error(TAG, AbstractC0147y.d("Listener change not found for command ", str), new Object[0]);
                return;
            }
        }
        if (z) {
            this.isExposureChangeEnabled = true;
            addExposureChangeListener();
        } else {
            this.isExposureChangeEnabled = false;
            removeExposureChangeListener();
        }
    }

    @Override // com.pubmatic.sdk.webrendering.ui.a
    public void onVisibilityChange(boolean z) throws JSONException {
        if (this.isAdVisible != z) {
            this.isAdVisible = z;
            POBLog.debug(TAG, "MRAID Ad Visibility changed ".concat(z ? "VISIBLE" : "INVISIBLE"), new Object[0]);
            if (this.scrollChangeListener != null) {
                updateExposureProperty(this.isAdVisible);
            }
            if (this.isViewableChangeTracking) {
                this.currentBridge.updateViewable(this.isAdVisible);
            }
            if (this.audioVolumeChangeListener != null) {
                updateRecentAudioVolumeToAd();
            }
        }
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.t
    public void open(String str, boolean z) {
        POBLog.debug(TAG, "Received MRAID event to open url : %s", str);
        w wVar = this.mraidControllerListener;
        if (wVar != null) {
            wVar.onOpen(str);
        }
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.t
    public void playVideo(String str, boolean z) {
        if (z) {
            notifyAdClick();
        }
        boolean z2 = false;
        if (com.pubmatic.sdk.common.utility.o.isNullOrEmpty(str)) {
            POBLog.debug(TAG, "Can't launch video player due to invalid URL", new Object[0]);
            return;
        }
        String interstitialOrientation = this.placementType.equals(DTBAdSize.AAX_INTERSTITIAL_AD_SIZE) ? getInterstitialOrientation(this.appContext) : null;
        Map<String, String> map = this.orientationProperties;
        if (map != null) {
            if (map.get("forceOrientation") != null) {
                interstitialOrientation = this.orientationProperties.get("forceOrientation");
            }
            z2 = Boolean.parseBoolean(this.orientationProperties.get("allowOrientationChange"));
        }
        Bundle bundle = new Bundle();
        if (interstitialOrientation != null) {
            bundle.putString(POBVideoPlayerActivity.FORCE_ORIENTATION_KEY, interstitialOrientation);
            bundle.putBoolean(POBVideoPlayerActivity.ALLOW_ORIENTATION_KEY, z2);
        }
        POBVideoPlayerActivity.startNewActivity(this.appContext, str, bundle, new b());
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.t
    public void resize(int i2, int i3, int i4, int i5, boolean z, boolean z2) throws JSONException {
        if (!this.placementType.equals("inline")) {
            POBLog.error(TAG, "Can't resize Interstitial ad.", new Object[0]);
            this.mraidBridge.notifyError("Can't perform resize on Interstitial ad.", "resize");
        } else {
            if (z2) {
                notifyAdClick();
            }
            manageResize(this.appContext, i2, i3, i4, i5, z);
        }
    }

    public void setMraidControllerListener(w wVar) {
        this.mraidControllerListener = wVar;
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.t
    public void setOrientation(boolean z, String str, boolean z2) {
        if (this.orientationProperties != null) {
            if (str.equalsIgnoreCase(DtbDeviceDataRetriever.ORIENTATION_PORTRAIT) || str.equalsIgnoreCase(DtbDeviceDataRetriever.ORIENTATION_LANDSCAPE)) {
                this.orientationProperties.put("forceOrientation", str);
            } else if (com.pubmatic.sdk.common.utility.o.getDeviceOrientation(this.appContext) == 2) {
                this.orientationProperties.put("forceOrientation", DtbDeviceDataRetriever.ORIENTATION_LANDSCAPE);
            } else {
                this.orientationProperties.put("forceOrientation", DtbDeviceDataRetriever.ORIENTATION_PORTRAIT);
            }
            this.orientationProperties.put("allowOrientationChange", String.valueOf(z));
        }
        com.pubmatic.sdk.webrendering.mraid.j mraidState = this.currentBridge.getMraidState();
        if ((!this.placementType.equals("inline") || !mraidState.equals(com.pubmatic.sdk.webrendering.mraid.j.EXPANDED)) && (!this.placementType.equals(DTBAdSize.AAX_INTERSTITIAL_AD_SIZE) || !mraidState.equals(com.pubmatic.sdk.webrendering.mraid.j.DEFAULT))) {
            POBLog.error(TAG, "Can't perform orientation properties. invalid MRAID state: %s", mraidState.a());
            return;
        }
        POBLog.debug(TAG, "setOrientation : allowOrientationChange :" + z + ", forceOrientation:" + str, new Object[0]);
        Context baseContext = ((MutableContextWrapper) this.currentBridge.webView.getContext()).getBaseContext();
        if (baseContext instanceof Activity) {
            Activity activity = (Activity) baseContext;
            forceOrientation(activity, str);
            allowOrientationChange(activity, z);
        }
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.t
    public void storePicture(String str, boolean z) {
        if (z) {
            notifyAdClick();
        }
        if (str != null && str.isEmpty()) {
            this.currentBridge.notifyError("Missing picture url.", "storePicture");
            return;
        }
        if (!com.pubmatic.sdk.common.utility.o.hasPermission(this.appContext, "android.permission.WRITE_EXTERNAL_STORAGE")) {
            this.currentBridge.notifyError("App does not have WRITE_EXTERNAL_STORAGE permission to store the picture.", "storePicture");
            return;
        }
        if (this.pobNetworkHandler == null) {
            this.pobNetworkHandler = new com.pubmatic.sdk.common.network.g(this.appContext);
        }
        if (this.imageNetworkListener == null) {
            this.imageNetworkListener = getImageNetworkListener();
        }
        com.pubmatic.sdk.common.network.b bVar = new com.pubmatic.sdk.common.network.b();
        bVar.setUrl(str);
        bVar.setTimeout(5000);
        bVar.setRequestTag(TAG);
        this.pobNetworkHandler.sendImageRequest(bVar, this.imageNetworkListener);
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.t
    public void unload() {
        String str = this.placementType;
        str.getClass();
        if (str.equals("inline")) {
            w wVar = this.mraidControllerListener;
            if (wVar != null) {
                wVar.onAdUnload();
                return;
            }
            return;
        }
        if (str.equals(DTBAdSize.AAX_INTERSTITIAL_AD_SIZE)) {
            close();
        } else {
            POBLog.error(TAG, "Can't perform unload as no specific placement type found.", new Object[0]);
        }
    }
}
