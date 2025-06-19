package com.amazon.device.ads;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Rect;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.ValueCallback;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.amazon.device.ads.SDKUtilities;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.quizlet.quizletandroid.R;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Map;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public abstract class DTBAdMRAIDController implements DTBActivityListener {
    static final String LOG_TAG = "DTBAdMRAIDController";
    public static final String MRAID_CLOSE = "window.mraid.close();";
    private static final String MRAID_READY = "window.mraidBridge.event.ready();";
    DTBAdView adView;
    LinearLayout closeIndicatorRegion;
    DTBMRAIDCloseButtonListener customButtonListener;
    private DtbOmSdkSessionManager dtbOmSdkSessionManager;
    private Rect lastRect;
    private MraidExposure lastReportedExposure;
    private Boolean lastViewabilityState;
    private boolean loadReportSubmitted;
    boolean pageLoaded = false;
    protected boolean useCustomClose = false;
    private int lastReportedSizeChangeWidth = -1;
    private int lastReportedSizeChangeHeight = -1;
    protected MraidStateType state = MraidStateType.LOADING;
    private boolean jsReady = false;
    private boolean isTwoPartExpand = false;

    /* renamed from: com.amazon.device.ads.DTBAdMRAIDController$2, reason: invalid class name */
    public static /* synthetic */ class AnonymousClass2 {
        static final /* synthetic */ int[] $SwitchMap$com$amazon$device$ads$MraidStateType;

        static {
            int[] iArr = new int[MraidStateType.values().length];
            $SwitchMap$com$amazon$device$ads$MraidStateType = iArr;
            try {
                iArr[MraidStateType.LOADING.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$com$amazon$device$ads$MraidStateType[MraidStateType.DEFAULT.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$com$amazon$device$ads$MraidStateType[MraidStateType.RESIZED.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                $SwitchMap$com$amazon$device$ads$MraidStateType[MraidStateType.EXPANDED.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                $SwitchMap$com$amazon$device$ads$MraidStateType[MraidStateType.HIDDEN.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
        }
    }

    public class MraidExposure {
        int percent;
        Rect rect;

        public MraidExposure(int i, Rect rect) {
            this.percent = i;
            this.rect = new Rect(rect);
        }
    }

    static {
        MraidCommand.registerCommand(MraidOpenCommand.getMraidName(), MraidOpenCommand.class);
        MraidCommand.registerCommand(MraidCloseCommand.getMraidName(), MraidCloseCommand.class);
        MraidCommand.registerCommand(MraidUnloadCommand.getMraidName(), MraidUnloadCommand.class);
        MraidCommand.registerCommand(MraidResizeCommand.getMraidName(), MraidResizeCommand.class);
        MraidCommand.registerCommand(MraidExpandCommand.getMraidName(), MraidExpandCommand.class);
        MraidCommand.registerCommand(MraidUseCustomCloseCommand.getMraidName(), MraidUseCustomCloseCommand.class);
        MraidCommand.registerCommand(MraidJSReadyCommand.getMraidName(), MraidJSReadyCommand.class);
        MraidCommand.registerCommand(MraidFirePixelCommand.getMraidName(), MraidFirePixelCommand.class);
    }

    public DTBAdMRAIDController(DTBAdView dTBAdView) {
        this.adView = dTBAdView;
        this.dtbOmSdkSessionManager = dTBAdView.getOmSdkManager();
    }

    private void evaluateJavascriptMethod(String str, JSONObject jSONObject) {
        evaluateJavascript(String.format(android.support.v4.media.session.a.k(str, "(%s);"), jSONObject.toString()));
    }

    private void fireEnforcedExposureChange(int i, Rect rect) {
        evaluateJavascript(String.format("window.mraidBridge.event.exposureChange(%d, { x:%d, y:%d, width:%d, height: %d}, null);", Integer.valueOf(i), Integer.valueOf(DTBAdUtil.pixelsToDeviceIndependenPixels(rect.left)), Integer.valueOf(DTBAdUtil.pixelsToDeviceIndependenPixels(rect.top)), Integer.valueOf(DTBAdUtil.pixelsToDeviceIndependenPixels(rect.right - rect.left)), Integer.valueOf(DTBAdUtil.pixelsToDeviceIndependenPixels(rect.bottom - rect.top))));
    }

    private void fireMaxSizeEvent() {
        SDKUtilities.SimpleSize maxSize = DTBAdUtil.getMaxSize(getAdView());
        evaluateJavascript(String.format("window.mraidBridge.property.setMaxSize({'width':%d, 'height':%d});", Integer.valueOf(maxSize.getWidth()), Integer.valueOf(maxSize.getHeight())));
    }

    private JSONObject formProperties(MraidProperty[] mraidPropertyArr) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        for (MraidProperty mraidProperty : mraidPropertyArr) {
            mraidProperty.formJSON(jSONObject);
        }
        return jSONObject;
    }

    private MraidProperty getCurrentStateProperty() {
        int i = AnonymousClass2.$SwitchMap$com$amazon$device$ads$MraidStateType[this.state.ordinal()];
        return i != 1 ? i != 2 ? i != 3 ? i != 4 ? i != 5 ? MraidProperty.STATE_DEFAULT_PROPERTY : MraidProperty.STATE_HIDDEN_PROPERTY : MraidProperty.STATE_EXPANDED_PROPERTY : MraidProperty.STATE_RESIZED_PROPERTY : MraidProperty.STATE_DEFAULT_PROPERTY : MraidProperty.STATE_LOADING_PROPERTY;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$evaluateJavascript$0(final String str) {
        if (getAdView() != null) {
            getAdView().evaluateJavascript(str, new ValueCallback<String>() { // from class: com.amazon.device.ads.DTBAdMRAIDController.1
                @Override // android.webkit.ValueCallback
                public void onReceiveValue(String str2) {
                    if (str2 == null || "null".equals(str2)) {
                        return;
                    }
                    String str3 = DTBAdMRAIDController.LOG_TAG;
                    StringBuilder sbY = android.support.v4.media.session.a.y("Value received:", str2, " for script ");
                    sbY.append(str);
                    DtbLog.debug(str3, sbY.toString());
                }
            });
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$onMRAIDUnload$2() {
        getAdView().loadUrl("about:blank");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ boolean lambda$setCloseIndicatorContent$3(View view, MotionEvent motionEvent) {
        if (motionEvent.getAction() != 0) {
            return true;
        }
        evaluateJavascript(MRAID_CLOSE);
        ((ViewGroup) view.getParent()).removeView(view);
        this.closeIndicatorRegion = null;
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$setState$1() {
        DTBAdView adView = getAdView();
        if (adView != null) {
            adView.setVisibility(8);
        }
    }

    public void addCloseIndicator(int i, int i2) {
        removeCloseIndicator();
        addCloseIndicator(i, i2, false);
    }

    public void cleanup() {
        this.closeIndicatorRegion = null;
        this.adView = null;
        this.customButtonListener = null;
    }

    public void closeExpandedPartTwo() {
    }

    public void commandCompleted(String str) {
        evaluateJavascript("window.mraidBridge.service.acknowledgement('" + str + "');");
    }

    public void createContentIndicator() {
        LinearLayout linearLayout = new LinearLayout(getAdView().getContext());
        this.closeIndicatorRegion = linearLayout;
        linearLayout.setVisibility(this.useCustomClose ? 4 : 0);
        this.closeIndicatorRegion.setOrientation(1);
    }

    public void createLoadReport() {
        String bidId = this.adView.getBidId();
        String hostname = this.adView.getHostname();
        if (bidId == null || this.loadReportSubmitted) {
            return;
        }
        DTBMetricsProcessor.getInstance().submitLatencyReportBidId(DTBMetricReport.addBid(bidId, hostname), DTBMetricsProcessor.REPORT_LOAD_LATENCY, (int) (assistantMode.refactored.a.f() - this.adView.getStartTime()));
        this.loadReportSubmitted = true;
    }

    public void evaluateJavascript(String str) {
        DtbLog.debug(LOG_TAG, "MRAID Evaluate JSScript:" + str);
        new Handler(Looper.getMainLooper()).post(new k(3, this, str));
    }

    public abstract void expand(Map<String, Object> map);

    public void fireEnforcedSizeChange(int i, int i2) {
        evaluateJavascript(String.format("window.mraidBridge.event.sizeChange(%d, %d);", Integer.valueOf(i), Integer.valueOf(i2)));
    }

    public void fireEnforcedViewableChange(boolean z) {
        evaluateJavascript("window.mraidBridge.event.viewableChange(" + (z ? "true" : "false") + ");");
    }

    public void fireErrorEvent(String str, String str2) {
        evaluateJavascript(AbstractC0147y.e("window.mraidBridge.event.error('", str2, "','", str, "');"));
    }

    public void fireExposureChange(int i, Rect rect) {
        int i2 = rect.right;
        if (this.jsReady) {
            fireEnforcedExposureChange(i, rect);
        } else {
            this.lastReportedExposure = new MraidExposure(i, rect);
        }
    }

    public void fireMRAIDReadyEvent() {
        evaluateJavascript(MRAID_READY);
    }

    public void fireMRAIDSupports() {
        evaluateJavascriptMethod("window.mraidBridge.property.setSupports", MraidProperty.SUPPORTS_PROPERTY.getData());
    }

    public void firePlacementType() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        jSONObject.put(DBUserFields.Names.USER_UPGRADE_TYPE, getPlacementType());
        evaluateJavascriptMethod("window.mraidBridge.property.setPlacementType", jSONObject);
    }

    public void fireScreenSizeEvent() {
        SDKUtilities.SimpleSize screenSize = DTBAdUtil.getScreenSize(getAdView());
        evaluateJavascript(String.format("window.mraidBridge.property.setScreenSize({'width':%d, 'height':%d});", Integer.valueOf(screenSize.getWidth()), Integer.valueOf(screenSize.getHeight())));
    }

    public void fireSizeChange(int i, int i2) {
        if (this.lastReportedSizeChangeWidth == i && this.lastReportedSizeChangeHeight == i2) {
            return;
        }
        this.lastReportedSizeChangeWidth = i;
        this.lastReportedSizeChangeHeight = i2;
        if (this.jsReady) {
            fireEnforcedSizeChange(i, i2);
        }
    }

    public void fireStateChangeEvent() {
        try {
            JSONObject jSONObjectFormProperties = formProperties(new MraidProperty[]{getCurrentStateProperty()});
            DtbLog.debug(LOG_TAG, "State was changed to " + jSONObjectFormProperties.toString() + " for controller " + this);
            evaluateJavascript("window.mraidBridge.event.stateChange(" + jSONObjectFormProperties.toString() + ");");
        } catch (JSONException e) {
            e.printStackTrace();
        }
    }

    public void fireViewableChange(boolean z) {
        Boolean bool = this.lastViewabilityState;
        if (bool == null || bool.booleanValue() != z) {
            if (this.jsReady) {
                fireEnforcedViewableChange(z);
            }
            this.lastViewabilityState = Boolean.valueOf(z);
        }
    }

    public DTBAdView getAdView() {
        return this.adView;
    }

    public Context getContext() {
        return getAdView().getContext();
    }

    public DtbOmSdkSessionManager getDtbOmSdkSessionManager() {
        return this.dtbOmSdkSessionManager;
    }

    public MraidStateType getInitialStateType() {
        return MraidStateType.DEFAULT;
    }

    public String getPlacementType() {
        return "";
    }

    public void impressionFired() {
        if (!getAdView().isVideo() && getDtbOmSdkSessionManager() != null) {
            getDtbOmSdkSessionManager().impressionOccured();
        }
        commandCompleted(MraidFirePixelCommand.getMraidName());
    }

    public boolean isTwoPartExpand() {
        return this.isTwoPartExpand;
    }

    public boolean isUseCustomClose() {
        return this.useCustomClose;
    }

    public void jsReady() {
        int i;
        commandCompleted("jsready");
        this.jsReady = true;
        Boolean bool = this.lastViewabilityState;
        if (bool != null) {
            fireEnforcedViewableChange(bool.booleanValue());
        }
        MraidExposure mraidExposure = this.lastReportedExposure;
        if (mraidExposure != null) {
            fireEnforcedExposureChange(mraidExposure.percent, mraidExposure.rect);
        }
        int i2 = this.lastReportedSizeChangeWidth;
        if (i2 <= 0 || (i = this.lastReportedSizeChangeHeight) <= 0) {
            return;
        }
        fireEnforcedSizeChange(i2, i);
    }

    @Override // com.amazon.device.ads.DTBActivityListener
    public void onActivityDestroyed(Activity activity) {
    }

    @Override // com.amazon.device.ads.DTBActivityListener
    public void onActivityPaused(Activity activity) {
    }

    @Override // com.amazon.device.ads.DTBActivityListener
    public void onActivityResumed(Activity activity) {
    }

    @Override // com.amazon.device.ads.DTBActivityListener
    public void onActivityStopped(Activity activity) {
    }

    public void onAdClicked() {
    }

    public void onAdFailedToLoad() {
    }

    public abstract void onAdLeftApplication();

    public void onAdLoaded() {
    }

    public void onAdOpened() {
    }

    public void onAdRemoved() {
    }

    public void onLoadError(String str, int i) {
        onLoadError();
    }

    public abstract void onMRAIDClose();

    public void onMRAIDUnload() {
        new Handler(Looper.getMainLooper()).post(new h(this, 0));
    }

    public abstract void onPageLoad();

    public void onPositionChanged(Rect rect) {
        Rect rect2 = this.lastRect;
        if (rect2 == null || !rect2.equals(rect)) {
            int i = rect.right - rect.left;
            int i2 = rect.bottom - rect.top;
            Rect rect3 = this.lastRect;
            boolean z = true;
            if (rect3 != null) {
                int i3 = rect3.right - rect3.left;
                int i4 = rect3.bottom - rect3.top;
                if (Math.abs(i3 - i) <= 1 && Math.abs(i4 - i2) <= 1) {
                    z = false;
                }
            }
            setCurrentPositionProperty();
            if (z) {
                fireSizeChange(DTBAdUtil.pixelsToDeviceIndependenPixels(i), DTBAdUtil.pixelsToDeviceIndependenPixels(i2));
            }
            this.lastRect = rect;
        }
    }

    public abstract void onResize(Map<String, Object> map);

    public void onVideoCompleted() {
    }

    public void onViewabilityChanged(boolean z) {
        DtbLog.debug("SET MRAID Visible " + z);
        fireViewableChange(z);
    }

    public void openUrl(String str) throws UnsupportedEncodingException {
        openUrl(str, false);
    }

    public void passLoadError() {
    }

    public void prepareMraid() throws JSONException {
        createLoadReport();
        this.pageLoaded = true;
        fireMaxSizeEvent();
        fireScreenSizeEvent();
        if (getAdView().isAdViewVisible()) {
            setCurrentPositionProperty();
        }
        fireMRAIDSupports();
        firePlacementType();
        setCurrentAppOrientation();
        setState(getInitialStateType());
        fireMRAIDReadyEvent();
        if (AdRegistration.isTestMode()) {
            evaluateJavascript("window.mraidBridge.service.debug('enable');");
        }
    }

    public void removeCloseIndicator() {
        ViewGroup viewGroup;
        LinearLayout linearLayout = this.closeIndicatorRegion;
        if (linearLayout == null || (viewGroup = (ViewGroup) linearLayout.getParent()) == null) {
            return;
        }
        viewGroup.removeView(this.closeIndicatorRegion);
    }

    public void setCloseIndicatorContent(View.OnTouchListener onTouchListener) {
        this.closeIndicatorRegion.setBackgroundColor(0);
        this.closeIndicatorRegion.setId(R.id.mraid_close_indicator);
        ImageView imageView = new ImageView(getAdView().getContext());
        imageView.setId(R.id.mraid_close_indicator);
        LinearLayout.LayoutParams layoutParams = new LinearLayout.LayoutParams(DTBAdUtil.sizeToDevicePixels(24), DTBAdUtil.sizeToDevicePixels(24));
        layoutParams.setMargins(DTBAdUtil.sizeToDevicePixels(14), DTBAdUtil.sizeToDevicePixels(14), 0, 0);
        this.closeIndicatorRegion.addView(imageView, layoutParams);
        if (getDtbOmSdkSessionManager() != null) {
            getDtbOmSdkSessionManager().addFriendlyObstruction(this.closeIndicatorRegion.findViewById(R.id.mraid_close_indicator), com.iab.omid.library.amazon.adsession.g.a);
        }
        imageView.setImageDrawable(com.facebook.appevents.g.f(getAdView().getContext(), 2131231642));
        if (onTouchListener != null) {
            this.closeIndicatorRegion.setOnTouchListener(onTouchListener);
        } else {
            this.closeIndicatorRegion.setOnTouchListener(new g(this, 0));
        }
    }

    public void setCurrentAppOrientation() throws JSONException {
        int iDetermineSimpleOrientation = DisplayUtils.determineSimpleOrientation();
        String str = iDetermineSimpleOrientation != 1 ? iDetermineSimpleOrientation != 2 ? "unspecified" : DtbDeviceDataRetriever.ORIENTATION_LANDSCAPE : DtbDeviceDataRetriever.ORIENTATION_PORTRAIT;
        boolean zIsRotationLocked = DisplayUtils.isRotationLocked();
        JSONObject jSONObject = new JSONObject();
        jSONObject.put(DtbDeviceData.DEVICE_DATA_ORIENTATION_KEY, str);
        jSONObject.put("locked", zIsRotationLocked);
        evaluateJavascriptMethod("window.mraidBridge.property.setCurrentAppOrientation", jSONObject);
    }

    public void setCurrentPositionProperty() {
        if (this.pageLoaded) {
            int[] iArr = new int[2];
            getAdView().getLocationOnScreen(iArr);
            setCurrentPositionProperty(iArr[0], iArr[1], getAdView().getWidth(), getAdView().getHeight());
        }
    }

    public void setCustomButtonListener(DTBMRAIDCloseButtonListener dTBMRAIDCloseButtonListener) {
        this.customButtonListener = dTBMRAIDCloseButtonListener;
    }

    public void setState(MraidStateType mraidStateType) {
        this.state = mraidStateType;
        if (mraidStateType == MraidStateType.HIDDEN) {
            new Handler(Looper.getMainLooper()).post(new h(this, 1));
        }
        fireStateChangeEvent();
    }

    public void setTwoPartExpand(boolean z) {
        this.isTwoPartExpand = z;
    }

    public void setUseCustomClose(boolean z) {
        DtbLog.debug("Set useCustomClose to " + z);
        this.useCustomClose = z;
        commandCompleted("useCustomClose");
        DTBMRAIDCloseButtonListener dTBMRAIDCloseButtonListener = this.customButtonListener;
        if (dTBMRAIDCloseButtonListener != null) {
            dTBMRAIDCloseButtonListener.useCustomButtonUpdated();
        }
    }

    public void startEndCardDisplayOMSDKSession() {
    }

    public void startOMSDKSession() {
    }

    public void stopOMSDKSession() {
    }

    public void onLoadError() {
        String bidId = this.adView.getBidId();
        String hostname = this.adView.getHostname();
        if (bidId != null) {
            DTBMetricsProcessor.getInstance().submitSimpleReportBidId(DTBMetricReport.addBid(bidId, hostname), DTBMetricsProcessor.REPORT_LOAD_FAILURE);
        }
        passLoadError();
    }

    public void openUrl(String str, boolean z) throws UnsupportedEncodingException {
        PackageManager packageManager = this.adView.getContext().getPackageManager();
        try {
            Uri uri = Uri.parse(str);
            if ("amazonmobile".equals(uri.getScheme()) && uri.getHost().equals("intent")) {
                String[] strArrSplit = str.split("intent=");
                if (strArrSplit.length > 1) {
                    String strDecode = null;
                    for (int i = 1; i < strArrSplit.length; i++) {
                        try {
                            String strSubstring = strArrSplit[i];
                            if (strSubstring.lastIndexOf("&") == strSubstring.length() - 1) {
                                strSubstring = strSubstring.substring(0, strSubstring.length() - 1);
                            }
                            strDecode = URLDecoder.decode(strSubstring, "UTF-8");
                            getContext().startActivity(new Intent("android.intent.action.VIEW", Uri.parse(strDecode)));
                            onAdLeftApplication();
                            break;
                        } catch (ActivityNotFoundException unused) {
                            DtbLog.debug("Intent:" + strDecode + " not found.");
                            fireErrorEvent("open", "requested activity not found");
                        } catch (UnsupportedEncodingException unused2) {
                            DtbLog.debug("Unsupported encoding");
                        }
                    }
                }
            } else if ("com.amazon.mobile.shopping".equals(uri.getScheme())) {
                try {
                    if (packageManager.getLaunchIntentForPackage("com.amazon.mShop.android.shopping") != null) {
                        Intent intent = new Intent("android.intent.action.VIEW");
                        intent.setData(uri);
                        AdRegistration.getCurrentActivity().startActivity(intent);
                    } else {
                        Intent intent2 = new Intent("android.intent.action.VIEW");
                        intent2.setData(uri);
                        int iIndexOf = str.indexOf("products/");
                        if (iIndexOf > 0) {
                            intent2.setData(Uri.parse("https://www.amazon.com/dp/" + str.substring(iIndexOf + 9)));
                            AdRegistration.getCurrentActivity().startActivity(intent2);
                        }
                    }
                    onAdLeftApplication();
                } catch (ActivityNotFoundException unused3) {
                    DtbLog.debug(LOG_TAG, "Activity not found com.amazon.mobile.shopping");
                    fireErrorEvent("open", "mshop activity not found");
                } catch (NullPointerException unused4) {
                    DtbLog.debug(LOG_TAG, "Current activity from AdRegistration not found");
                    fireErrorEvent("open", "current activity from AdRegistration not found");
                }
            } else if ("market".equals(uri.getScheme()) || "amzn".equals(uri.getScheme())) {
                try {
                    try {
                        Intent intent3 = new Intent("android.intent.action.VIEW");
                        intent3.setData(uri);
                        AdRegistration.getCurrentActivity().startActivity(intent3);
                        onAdLeftApplication();
                    } catch (ActivityNotFoundException unused5) {
                        DtbLog.debug(LOG_TAG, "App stores and browsers not found");
                        fireErrorEvent("open", "app stores and browsers not found");
                    } catch (NullPointerException unused6) {
                        DtbLog.debug(LOG_TAG, "Current activity from AdRegistration not found");
                        fireErrorEvent("open", "current activity from AdRegistration not found");
                    }
                } catch (ActivityNotFoundException unused7) {
                    DTBAdUtil.directAppStoreLinkToBrowser(this, uri);
                } catch (NullPointerException unused8) {
                    DtbLog.debug(LOG_TAG, "Current activity from AdRegistration not found");
                    fireErrorEvent("open", "current activity from AdRegistration not found");
                }
            } else {
                if (uri.getScheme() == null) {
                    uri = Uri.parse("https:" + str);
                }
                if (z) {
                    try {
                        new androidx.browser.customtabs.k(0, false).c().v(getContext(), uri);
                        onAdLeftApplication();
                    } catch (Exception e) {
                        String str2 = "Failed to execute open command: invalid url " + str;
                        fireErrorEvent("open", str2);
                        com.amazon.aps.shared.a.e(1, 1, str2, e);
                    }
                } else {
                    try {
                        Intent intent4 = new Intent("android.intent.action.VIEW", uri);
                        intent4.addFlags(268435456);
                        getContext().startActivity(intent4);
                        onAdLeftApplication();
                    } catch (Exception e2) {
                        String str3 = "Failed to execute open command: invalid url " + str;
                        fireErrorEvent("open", str3);
                        com.amazon.aps.shared.a.e(1, 1, str3, e2);
                    }
                }
            }
            commandCompleted("open");
        } catch (Exception unused9) {
            fireErrorEvent("open", "invalid url " + str);
            commandCompleted("open");
        }
    }

    public void addCloseIndicator(int i, int i2, boolean z) {
        removeCloseIndicator();
        addCloseIndicator(i, i2, null, z);
    }

    @SuppressLint({"ResourceType"})
    public void addCloseIndicator(int i, int i2, View.OnTouchListener onTouchListener, boolean z) {
        createContentIndicator();
        DTBAdUtil.getRootView(getAdView()).addView(this.closeIndicatorRegion, DTBAdUtil.sizeToDevicePixels(50), DTBAdUtil.sizeToDevicePixels(50));
        this.closeIndicatorRegion.setX(i - DTBAdUtil.sizeToDevicePixels(50));
        this.closeIndicatorRegion.setY(i2);
        setCloseIndicatorContent(onTouchListener);
    }

    public void setCurrentPositionProperty(float f, float f2) {
        if (this.pageLoaded) {
            int[] iArr = new int[2];
            getAdView().getLocationOnScreen(iArr);
            setCurrentPositionProperty(iArr[0], iArr[1], f, f2);
        }
    }

    public void setCurrentPositionProperty(int i, int i2, float f, float f2) {
        if (this.pageLoaded) {
            evaluateJavascript(String.format("window.mraidBridge.property.setCurrentPosition({'xPos':%.1f, 'yPos':%.1f, 'width': %.1f, 'height': %.1f});", Float.valueOf(DTBAdUtil.pixelsToDeviceIndependenPixels(i)), Float.valueOf(DTBAdUtil.pixelsToDeviceIndependenPixels(i2)), Float.valueOf(DTBAdUtil.pixelsToDeviceIndependenPixels((int) f)), Float.valueOf(DTBAdUtil.pixelsToDeviceIndependenPixels((int) f2))));
        }
    }
}
