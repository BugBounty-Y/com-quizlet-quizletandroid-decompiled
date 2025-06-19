package com.amazon.device.ads;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.HandlerThread;
import android.preference.PreferenceManager;
import androidx.annotation.NonNull;
import com.amazon.device.ads.AdError;
import com.amazon.device.ads.AdRegistration;
import com.amazon.device.ads.DtbCommonUtils;
import com.amazon.device.ads.DtbMetrics;
import com.davemorrissey.labs.subscaleview.BuildConfig;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.UUID;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public class DTBAdRequest implements DTBAdLoader {
    private static final String AAX_VIDEO_INVENTORY_TYPE = "inventoryType";
    private static final String AAX_VIDEO_SKIP_AFTER = "skipAfter";
    private static final int DEFAULT_RERESH_DURATION = 60;
    private static final String LOG_TAG = "DTBAdRequest";
    private static final int MIN_REFRESH_DURATION = 20;
    private static final String PJ_KEY = "pj";
    private static final long WEEK = 604800000;
    static JSONArray mRaidArray = null;
    private static JSONArray mRaidCustomArray = null;
    private static boolean mRaidDefined = false;
    private String aaxHostname;
    private volatile AdError adError;
    private DTBAdNetworkInfo adNetworkInfo;
    private DTBAdResponse adResponse;
    private final List<DTBAdSize> adSizes;
    private DTBAdCallback callback;
    private Context context;
    private String correlationId;
    private final Map<String, String> customTargets;
    private boolean isAutoRefresh;
    private Handler mHandler;
    private HandlerThread mHandlerThread;
    private final Runnable mRefreshRunnable;
    private int refreshDuration;
    private boolean refreshFlag;
    private boolean requestHasBeenUsed;
    private final Map<String, String> sizeSlotUUIDMap;
    private String slotGroup;
    private long startLoadAdTime;
    private boolean submitMetrics;
    private static final String[] MRAID_VALID_VERSIONS = {BuildConfig.VERSION_NAME, DtbConstants.APS_ADAPTER_VERSION_2, "3.0"};
    private static Integer reqCount = 0;

    /* renamed from: com.amazon.device.ads.DTBAdRequest$1, reason: invalid class name */
    public static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$amazon$device$ads$MRAIDPolicy;

        static {
            int[] iArr = new int[MRAIDPolicy.values().length];
            $SwitchMap$com$amazon$device$ads$MRAIDPolicy = iArr;
            try {
                iArr[MRAIDPolicy.AUTO_DETECT.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$com$amazon$device$ads$MRAIDPolicy[MRAIDPolicy.DFP.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$com$amazon$device$ads$MRAIDPolicy[MRAIDPolicy.CUSTOM.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                $SwitchMap$com$amazon$device$ads$MRAIDPolicy[MRAIDPolicy.NONE.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
        }
    }

    public class WrapperReport {
        String expectedPackage;
        String wrapperPackage;

        public WrapperReport() {
        }
    }

    public DTBAdRequest(@NonNull Context context, @NonNull DTBAdNetworkInfo dTBAdNetworkInfo) {
        this.adSizes = new ArrayList();
        this.customTargets = new HashMap();
        this.sizeSlotUUIDMap = new HashMap();
        this.adError = null;
        this.requestHasBeenUsed = false;
        this.submitMetrics = true;
        this.isAutoRefresh = false;
        this.refreshFlag = false;
        this.refreshDuration = 0;
        this.mRefreshRunnable = new j(this, 0);
        this.slotGroup = null;
        this.correlationId = UUID.randomUUID().toString() + UUID.randomUUID().toString();
        if (context == null) {
            throw new IllegalArgumentException("unable to initialize ad request with null app context");
        }
        try {
            if (!AdRegistration.isInitialized()) {
                DtbLog.warn("mDTB was not initialized, please use AdRegistration.getInstance(...) before using other SDK calls");
                return;
            }
            if (AdRegistration.getContext() == null) {
                AdRegistration.setContext(context);
            }
            this.context = context;
            setNetworkInfo(dTBAdNetworkInfo);
            if (mRaidDefined) {
                return;
            }
            defineMraid();
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, "Fail to initialize DTBAdRequest class with context argument", e);
        }
    }

    private void addMraidParameters(Map<String, Object> map) {
        JSONArray jSONArray = mRaidArray;
        if (jSONArray == null || jSONArray.length() <= 0) {
            return;
        }
        map.put("mraid", mRaidArray);
    }

    private void addPrivacyParameters(Map<String, Object> map) throws JSONException {
        Context context = this.context;
        if (context != null) {
            addGDPRParametersFromPreferences(map, PreferenceManager.getDefaultSharedPreferences(context));
            HashMap<String, Object> mapAddGPPParametersFromPreferences = DtbCommonUtils.addGPPParametersFromPreferences(PreferenceManager.getDefaultSharedPreferences(this.context));
            if (!DtbCommonUtils.isNullOrEmpty(mapAddGPPParametersFromPreferences)) {
                try {
                    map.put("regs", DtbCommonUtils.getParamsAsJson(mapAddGPPParametersFromPreferences));
                } catch (JSONException e) {
                    com.amazon.aps.shared.a.e(2, 1, "Fail to get global privacy platform params", e);
                }
            }
            addDsaTransparencyParams(map);
        }
    }

    private AdError createAdError(AdError.ErrorCode errorCode, String str) {
        AdError adError = new AdError(errorCode, str);
        adError.setAdLoader(DtbCommonUtils.createAutoRefreshAdLoader(this));
        return adError;
    }

    private WrapperReport detectWrapper(Object obj) {
        Context applicationContext = AdRegistration.getContext().getApplicationContext();
        try {
            String name = obj.getClass().getPackage().getName();
            String str = applicationContext.getApplicationInfo().packageName;
            StringTokenizer stringTokenizer = new StringTokenizer(name, ".");
            StringTokenizer stringTokenizer2 = new StringTokenizer(str, ".");
            if (stringTokenizer.countTokens() < 2 || stringTokenizer2.countTokens() < 2) {
                WrapperReport wrapperReport = new WrapperReport();
                wrapperReport.expectedPackage = str;
                wrapperReport.wrapperPackage = name;
                return wrapperReport;
            }
            for (int i = 0; i < 2; i++) {
                if (!stringTokenizer.nextToken().equals(stringTokenizer2.nextToken())) {
                    WrapperReport wrapperReport2 = new WrapperReport();
                    wrapperReport2.expectedPackage = name;
                    wrapperReport2.wrapperPackage = str;
                    return wrapperReport2;
                }
            }
            return null;
        } catch (Exception unused) {
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: executeCallback, reason: merged with bridge method [inline-methods] */
    public void lambda$triggerCallBack$2(DtbMetrics dtbMetrics) {
        WrapperReport wrapperReportDetectWrapper;
        long jCurrentTimeMillis = System.currentTimeMillis();
        if (this.callback == null) {
            DtbLog.error("No callback -DTBAdCallback- provided to loadAd() to handle success or failure.");
        } else if (this.adError == null || this.adError.getCode() != AdError.ErrorCode.NO_ERROR) {
            DtbLog.debug("Invoking onFailure() callback with errorCode: " + this.adError.getCode() + "[" + this.adError.getMessage() + "]");
            this.callback.onFailure(this.adError);
        } else {
            DtbLog.debug("Invoking onSuccess() callback for pricepoints: [" + this.adResponse.getDefaultPricePoints() + "]");
            this.callback.onSuccess(this.adResponse);
            DtbLog.debug("Performing SDK wrapping detection. Will submit a report if needed.");
            if (wrapperDetectionNeeded() && (wrapperReportDetectWrapper = detectWrapper(this.callback)) != null) {
                if (Math.random() <= DTBMetricsConfiguration.getClientConfigVal("wrapping_pixel", DTBMetricsConfiguration.WRAPPING_PIXEL_DEFAULT_VALUE.intValue(), "sample_rates").intValue() / 100.0f) {
                    HashMap map = new HashMap();
                    map.put("expected_package", wrapperReportDetectWrapper.expectedPackage);
                    map.put("wrapper_package", wrapperReportDetectWrapper.wrapperPackage);
                    DTBMetricsProcessor.getInstance().submitErrorReport("alert_sdk_wrapping_v2", map, DTBMetricReport.addBid(null, DtbCommonUtils.getHostNameFromUrl(dtbMetrics.getInstPxlUrl())));
                }
            }
        }
        sendBidEvent(jCurrentTimeMillis);
    }

    private String getAdSize(JSONObject jSONObject, List<DTBAdSize> list) {
        try {
            if (jSONObject.has("sz") && !DtbCommonUtils.isNullOrEmpty(jSONObject.getString("sz"))) {
                return jSONObject.getString("sz");
            }
            com.amazon.aps.shared.a.e(1, 1, "Invalid sz params from AAX Bid Response.".concat("BidId = " + this.adResponse.getBidId()), null);
            if (!DTBMetricsConfiguration.getInstance().isFeatureEnabled(DTBMetricsConfiguration.FEATURE_ENABLE_DEFAULT_AD_SIZE)) {
                return "0x0";
            }
            Iterator<DTBAdSize> it2 = list.iterator();
            if (!it2.hasNext()) {
                return "0x0";
            }
            DTBAdSize next = it2.next();
            if (next.isInterstitialAd()) {
                return "9999x9999";
            }
            return next.getWidth() + "x" + next.getHeight();
        } catch (Exception e) {
            com.amazon.aps.shared.a.e(1, 1, "Failed to get ad size passed from bid Request", e);
            return "0x0";
        }
    }

    private void increaseReqCount() {
        synchronized (reqCount) {
            reqCount = Integer.valueOf(reqCount.intValue() + 1);
        }
    }

    private void internalLoadAd() {
        DtbLog.debug("Loading DTB ad.");
        DtbThreadService.getInstance().execute(new j(this, 1));
        DtbLog.debug("Dispatched the loadAd task on a background thread.");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$internalLoadAd$1() {
        DtbLog.info("Fetching DTB ad.");
        try {
            loadAdRequest();
            DtbLog.debug("DTB Ad call is complete");
        } catch (Exception unused) {
            DtbLog.error(LOG_TAG, "Unknown exception in DTB ad call process.");
        }
    }

    private void loadAd(DTBAdCallback dTBAdCallback, String str) throws DTBLoadException, JSONException, IllegalArgumentException {
        AdRegistration.SlotGroup slotGroup = AdRegistration.getSlotGroup(this.slotGroup);
        if (slotGroup == null) {
            throw new DTBLoadException("Slot group is not found");
        }
        DTBAdSize sizeBySlotUUID = slotGroup.getSizeBySlotUUID(str);
        if (sizeBySlotUUID == null) {
            throw new DTBLoadException("Slot group does not contain requested slotUUID");
        }
        setSizes(sizeBySlotUUID);
        loadAd(dTBAdCallback);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:141:0x03c5  */
    /* JADX WARN: Removed duplicated region for block: B:144:0x03cf  */
    /* JADX WARN: Removed duplicated region for block: B:170:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Unreachable blocks removed: 2, instructions: 2 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void loadAdRequest() throws java.lang.Exception {
        /*
            Method dump skipped, instructions count: 981
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.amazon.device.ads.DTBAdRequest.loadAdRequest():void");
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: refreshAd, reason: merged with bridge method [inline-methods] */
    public void lambda$new$0() {
        Activity activity;
        if (!this.isAutoRefresh || this.refreshDuration <= 0) {
            return;
        }
        Context context = this.context;
        if (context instanceof Activity) {
            activity = (Activity) context;
            if (activity.isFinishing() || DtbCommonUtils.isActivityDestroyed(activity)) {
                DtbLog.info("Stopping DTB auto refresh...");
                stop();
                return;
            }
        } else {
            activity = null;
        }
        this.refreshFlag = true;
        if (activity == null || activity.hasWindowFocus()) {
            internalLoadAd();
        } else {
            DtbLog.debug("Skipping DTB auto refresh...activity not in focus");
            scheduleAdRefreshIfEnabled();
        }
    }

    private void removeAaxHostNameFromSharedPreferences() {
        try {
            if (DtbConstants.REMOVE_AAX_END_POINT_FROM_SHARED_PREF.contains(DtbSharedPreferences.getInstance().getAaxHostname())) {
                DtbSharedPreferences.getInstance().removeAAXHostName();
            }
        } catch (Exception e) {
            com.amazon.aps.shared.a.e(1, 1, "Exception while removing HostName from sharedPreference", e);
        }
    }

    public static void resetMraid() {
        mRaidArray = null;
        mRaidDefined = false;
    }

    private void scheduleAdRefreshIfEnabled() {
        if (!this.isAutoRefresh || this.refreshDuration <= 0) {
            return;
        }
        stopAutoRefresh();
        Handler handler = this.mHandler;
        if (handler != null) {
            handler.postDelayed(this.mRefreshRunnable, this.refreshDuration * 1000);
        }
    }

    private void sendBidEvent(long j) {
        com.amazon.aps.shared.metrics.model.f event;
        try {
            com.airbnb.lottie.network.d dVar = new com.airbnb.lottie.network.d(17);
            String correlationId = getCorrelationId();
            Intrinsics.checkNotNullParameter(correlationId, "correlationId");
            ((com.amazon.aps.shared.metrics.model.k) dVar.b).f = correlationId;
            ((com.amazon.aps.shared.metrics.model.k) dVar.b).b = this.adNetworkInfo.getAdNetworkName();
            String bidId = null;
            aVar = null;
            aVar = null;
            aVar = null;
            aVar = null;
            com.amazon.aps.ads.model.a aVar = null;
            if (this.adError == null || this.adError.getCode() != AdError.ErrorCode.NO_ERROR) {
                event = new com.amazon.aps.shared.metrics.model.f(com.amazon.aps.shared.metrics.model.m.b, this.aaxHostname);
            } else {
                DTBAdSize dTBAdSize = this.adResponse.getDTBAds().get(0);
                event = new com.amazon.aps.shared.metrics.model.f(com.amazon.aps.shared.metrics.model.m.a, this.aaxHostname);
                AdType dTBAdType = dTBAdSize.getDTBAdType();
                int height = dTBAdSize.getHeight();
                int width = dTBAdSize.getWidth();
                if (dTBAdType != null) {
                    try {
                        int i = com.amazon.aps.ads.b.b[dTBAdType.ordinal()];
                        if (i != 1) {
                            if (i == 2 || i == 3) {
                                aVar = com.amazon.aps.ads.model.a.d;
                            }
                        } else if (height == 50 && width == 320) {
                            aVar = com.amazon.aps.ads.model.a.a;
                        } else if (height == 250 && width == 300) {
                            aVar = com.amazon.aps.ads.model.a.b;
                        } else if (height == 90 && width == 728) {
                            aVar = com.amazon.aps.ads.model.a.c;
                        }
                    } catch (RuntimeException e) {
                        com.amazon.aps.shared.a.e(1, 1, "Error on getting AdFormat", e);
                    }
                }
                if (aVar != null) {
                    String adFormat = aVar.toString();
                    Intrinsics.checkNotNullParameter(adFormat, "adFormat");
                    ((com.amazon.aps.shared.metrics.model.k) dVar.b).e = adFormat;
                }
                bidId = this.adResponse.getBidId();
                ((com.amazon.aps.shared.metrics.model.k) dVar.b).d = Boolean.valueOf(this.adResponse.isVideo());
            }
            event.f = Boolean.valueOf(this.isAutoRefresh);
            event.b = this.startLoadAdTime;
            event.c = j;
            Intrinsics.checkNotNullParameter(event, "event");
            ((com.amazon.aps.shared.metrics.model.k) dVar.b).g = event;
            com.amazon.aps.shared.a.a(bidId, dVar);
        } catch (RuntimeException e2) {
            com.amazon.aps.shared.a.e(1, 1, "Error in sending the bid event in ad request", e2);
        }
    }

    public static void setMRAIDSupportedVersions(String[] strArr) {
        if (strArr != null && strArr.length > 0) {
            mRaidCustomArray = new JSONArray();
            List listAsList = Arrays.asList(MRAID_VALID_VERSIONS);
            for (String str : strArr) {
                if (str == null) {
                    DtbLog.error(LOG_TAG, "null custom version supplied");
                } else {
                    if (!listAsList.contains(str)) {
                        DtbLog.warn(LOG_TAG, "custom version \"" + str + "\" is not valid");
                    }
                    mRaidCustomArray.put(str);
                }
            }
        }
        resetMraid();
    }

    private void setRefreshDuration(int i) {
        if (i >= 20) {
            this.refreshDuration = i;
        } else {
            DtbLog.warn(LOG_TAG, "Defaulting auto refresh duration to 60 seconds.");
            this.refreshDuration = DEFAULT_RERESH_DURATION;
        }
    }

    private void stopAutoRefresh() {
        Handler handler = this.mHandler;
        if (handler != null) {
            handler.removeCallbacksAndMessages(null);
        }
        this.refreshFlag = false;
    }

    private void triggerCallBack(DtbMetrics dtbMetrics) {
        scheduleAdRefreshIfEnabled();
        DtbLog.info(LOG_TAG, "Forwarding the error handling to view on main thread.");
        DtbThreadService.executeOnMainThread(new k(0, this, dtbMetrics));
        if (this.submitMetrics) {
            DtbMetrics.Submitter.INSTANCE.submitMetrics(dtbMetrics);
        }
    }

    private void useDFP(DtbCommonUtils.APIVersion aPIVersion) {
        if (aPIVersion.majorVersion > 0) {
            JSONArray jSONArray = new JSONArray();
            mRaidArray = jSONArray;
            jSONArray.put(BuildConfig.VERSION_NAME);
            int i = aPIVersion.majorVersion;
            if ((i == 7 && aPIVersion.minorVersion >= 8) || i > 7) {
                mRaidArray.put(DtbConstants.APS_ADAPTER_VERSION_2);
            }
            if (aPIVersion.majorVersion >= 15) {
                mRaidArray.put("3.0");
            }
        }
    }

    private boolean wrapperDetectionNeeded() {
        DtbSharedPreferences dtbSharedPreferences = DtbSharedPreferences.getInstance();
        Long wrapperDetectionLastPing = dtbSharedPreferences.getWrapperDetectionLastPing();
        long jF = assistantMode.refactored.a.f();
        boolean z = true;
        if (wrapperDetectionLastPing != null && jF - wrapperDetectionLastPing.longValue() <= WEEK) {
            z = false;
        }
        if (z) {
            dtbSharedPreferences.saveWrapperDetectionLastPing(jF);
        }
        return z;
    }

    public void addDsaTransparencyParams(Map<String, Object> map) throws JSONException {
        try {
            JSONObject jSONObject = map.containsKey("regs") ? (JSONObject) map.get("regs") : new JSONObject();
            if (!DtbCommonUtils.isNullOrEmpty(AdRegistration.getDsaTransparencyData())) {
                jSONObject.put("dsa", AdRegistration.getDsaTransparencyData());
            }
            if (DtbCommonUtils.isNullOrEmpty(jSONObject)) {
                return;
            }
            map.put("regs", jSONObject);
        } catch (JSONException e) {
            com.amazon.aps.shared.a.e(2, 1, "API Failure : Failed to add DSA Transparency params", e);
        }
    }

    public void addGDPRParametersFromPreferences(Map<String, Object> map, SharedPreferences sharedPreferences) throws JSONException {
        JSONObject jSONObject = null;
        String string = sharedPreferences.getString("IABConsent_SubjectToGDPR", null);
        Object obj = sharedPreferences.contains("IABTCF_gdprApplies") ? sharedPreferences.getAll().get("IABTCF_gdprApplies") : null;
        String string2 = sharedPreferences.getString("IABConsent_ConsentString", null);
        String string3 = sharedPreferences.getString("IABTCF_TCString", null);
        String encodedNonIABString = AdRegistration.getEncodedNonIABString();
        try {
            if (string3 != null || string2 != null) {
                jSONObject = new JSONObject();
                if (string3 != null) {
                    jSONObject.put("c", string3);
                } else if (string2 != null) {
                    jSONObject.put("c", string2);
                }
            } else if (encodedNonIABString != null) {
                jSONObject = new JSONObject();
                jSONObject.put("c", encodedNonIABString);
            }
            if (string != null || obj != null) {
                if (jSONObject == null) {
                    jSONObject = new JSONObject();
                }
                if (obj != null) {
                    try {
                        if ((obj instanceof Integer) && (((Integer) obj).intValue() == 1 || ((Integer) obj).intValue() == 0)) {
                            jSONObject.put("e", obj);
                        } else if (((obj instanceof String) && ((String) obj).equals("1")) || ((String) obj).equals("0")) {
                            jSONObject.put("e", obj);
                        } else {
                            DtbLog.info("IABTCF_gdprApplies should be a 1 or 0 as per IAB guideline");
                        }
                    } catch (ClassCastException unused) {
                        DtbLog.info("IABTCF_gdprApplies should be a number as per IAB guideline");
                    }
                } else if (string != null) {
                    jSONObject.put("e", string);
                }
            }
            if (jSONObject == null || jSONObject.length() == 0) {
                return;
            }
            map.put("gdpr", jSONObject);
        } catch (JSONException unused2) {
            DtbLog.error("INVALID JSON formed for GDPR clause");
        }
    }

    public void addLegoFlag(Map<String, Object> map, boolean z) {
    }

    public void defineMraid() {
        DtbCommonUtils.APIVersion aPIVersion = new DtbCommonUtils.APIVersion();
        Integer integerFieldValue = null;
        for (String str : dfpCandidateList()) {
            if (integerFieldValue != null) {
                break;
            }
            integerFieldValue = DtbCommonUtils.getIntegerFieldValue(str, "GOOGLE_PLAY_SERVICES_VERSION_CODE");
        }
        if (integerFieldValue == null) {
            for (char c = 'a'; c <= 'z'; c = (char) (c + 1)) {
                integerFieldValue = DtbCommonUtils.getIntegerFieldValue("com.google.android.gms.common.zz" + c, "GOOGLE_PLAY_SERVICES_VERSION_CODE");
                if (integerFieldValue != null) {
                    break;
                }
            }
        }
        if (integerFieldValue != null) {
            int iIntValue = integerFieldValue.intValue() / 1000;
            aPIVersion.minorVersion = (iIntValue % 1000) / 100;
            aPIVersion.majorVersion = iIntValue / 1000;
            DtbLog.debug("Google DFP major version:" + aPIVersion.majorVersion + "minor version:" + aPIVersion.minorVersion);
        } else {
            DtbLog.debug("Not able to identify Google DFP version");
        }
        mRaidDefined = true;
        int i = AnonymousClass1.$SwitchMap$com$amazon$device$ads$MRAIDPolicy[AdRegistration.getMRAIDPolicy().ordinal()];
        if (i == 1) {
            if (isServerless() || integerFieldValue == null) {
                return;
            }
            useDFP(aPIVersion);
            return;
        }
        if (i != 2) {
            if (i != 3) {
                return;
            }
            mRaidArray = mRaidCustomArray;
        } else if (integerFieldValue != null) {
            useDFP(aPIVersion);
        }
    }

    public String[] dfpCandidateList() {
        return new String[]{"com.google.android.gms.common.GoogleApiAvailability", "com.google.android.gms.common.GoogleApiAvailabilityLight", "com.google.android.gms.common.GooglePlayServicesUtil", "com.google.android.gms.common.GooglePlayServicesUtilLight"};
    }

    public DTBAdNetworkInfo getAdNetworkInfo() {
        return this.adNetworkInfo;
    }

    public List<DTBAdSize> getAdSizes() {
        return this.adSizes;
    }

    public String getCorrelationId() {
        return this.correlationId;
    }

    public Map<String, String> getCustomTargets() {
        return this.customTargets;
    }

    public int getRefreshDuration() {
        return this.refreshDuration;
    }

    @Override // com.amazon.device.ads.DTBAdLoader
    public String getSlotGroupName() {
        return this.slotGroup;
    }

    public boolean isServerless() throws ClassNotFoundException {
        for (String str : AdRegistration.getServerlessMarkers()) {
            try {
                Class.forName(str);
                JSONArray jSONArray = new JSONArray();
                mRaidArray = jSONArray;
                jSONArray.put(BuildConfig.VERSION_NAME);
                mRaidArray.put(DtbConstants.APS_ADAPTER_VERSION_2);
                mRaidArray.put("3.0");
                return true;
            } catch (Exception unused) {
            }
        }
        return false;
    }

    @Override // com.amazon.device.ads.DTBAdLoader
    public void loadSmartBanner(DTBAdCallback dTBAdCallback) throws DTBLoadException, JSONException {
        int i;
        int i2;
        try {
            this.startLoadAdTime = System.currentTimeMillis();
            if (DtbDeviceDataRetriever.isTablet()) {
                i = 728;
                i2 = 90;
            } else {
                i = DtbConstants.DEFAULT_PLAYER_WIDTH;
                i2 = 50;
            }
            loadAd(dTBAdCallback, i, i2);
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, "Fail to execute loadSmartBanner method", e);
        }
    }

    public void onRequestFormed(HashMap<String, Object> map) {
    }

    @Override // com.amazon.device.ads.DTBAdLoader
    public void pauseAutoRefresh() {
        this.isAutoRefresh = false;
        this.refreshFlag = false;
    }

    @Override // com.amazon.device.ads.DTBAdLoader
    public void putCustomTarget(@NonNull String str, @NonNull String str2) {
        try {
            this.customTargets.put(str, str2);
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute putCustomTarget method", e);
        }
    }

    public void recycle() {
        this.requestHasBeenUsed = false;
    }

    @Override // com.amazon.device.ads.DTBAdLoader
    public void resumeAutoRefresh() {
        try {
            setAutoRefresh(this.refreshDuration);
            lambda$new$0();
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, "Fail to execute resumeAutoRefresh method", e);
        }
    }

    public void setAdSizes(List<DTBAdSize> list) {
        this.adSizes.clear();
        for (DTBAdSize dTBAdSize : list) {
            if (dTBAdSize != null) {
                this.adSizes.add(dTBAdSize);
            }
        }
    }

    @Override // com.amazon.device.ads.DTBAdLoader
    public void setAutoRefresh() {
        try {
            this.isAutoRefresh = true;
            setRefreshDuration(DEFAULT_RERESH_DURATION);
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute setAutoRefresh method", e);
        }
    }

    public void setCorrelationId(String str) {
        this.correlationId = str;
    }

    public void setCustomTargets(Map<String, String> map) {
        this.customTargets.clear();
        for (Map.Entry<String, String> entry : map.entrySet()) {
            this.customTargets.put(entry.getKey(), entry.getValue());
        }
    }

    @Override // com.amazon.device.ads.DTBAdLoader
    public synchronized void setNetworkInfo(DTBAdNetworkInfo dTBAdNetworkInfo) {
        if (dTBAdNetworkInfo != null) {
            this.adNetworkInfo = dTBAdNetworkInfo;
        } else {
            dTBAdNetworkInfo = new DTBAdNetworkInfo(DTBAdNetwork.UNKNOWN);
            this.adNetworkInfo = dTBAdNetworkInfo;
        }
    }

    public void setRefreshFlag(boolean z) {
        this.refreshFlag = z;
    }

    @Override // com.amazon.device.ads.DTBAdLoader
    public void setSizes(DTBAdSize... dTBAdSizeArr) throws IllegalArgumentException {
        this.adSizes.clear();
        DtbLog.info(LOG_TAG, "Setting " + dTBAdSizeArr.length + " AdSize(s) to the ad request.");
        for (DTBAdSize dTBAdSize : dTBAdSizeArr) {
            if (dTBAdSize == null) {
                throw new IllegalArgumentException("DTBAdSize cannot be null.");
            }
            this.adSizes.add(dTBAdSize);
        }
    }

    @Override // com.amazon.device.ads.DTBAdLoader
    public void setSlotGroup(String str) {
        this.slotGroup = str;
    }

    @Override // com.amazon.device.ads.DTBAdLoader
    public void stop() {
        try {
            stopAutoRefresh();
            HandlerThread handlerThread = this.mHandlerThread;
            if (handlerThread != null) {
                handlerThread.quit();
                DtbLog.debug("Stopping DTB auto refresh");
            }
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute stop method", e);
        }
    }

    @Override // com.amazon.device.ads.DTBAdLoader
    public void setAutoRefresh(int i) {
        try {
            this.isAutoRefresh = true;
            setRefreshDuration(i);
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute setAutoRefresh method with seconds argument", e);
        }
    }

    private void loadAd(DTBAdCallback dTBAdCallback, int i, int i2) throws DTBLoadException, JSONException, IllegalArgumentException {
        loadAd(dTBAdCallback, i, i2, AdType.DISPLAY);
    }

    private void loadAd(DTBAdCallback dTBAdCallback, int i, int i2, AdType adType) throws DTBLoadException, JSONException, IllegalArgumentException {
        AdRegistration.SlotGroup slotGroup = AdRegistration.getSlotGroup(this.slotGroup);
        if (slotGroup != null) {
            DTBAdSize sizeByWidthHeightType = slotGroup.getSizeByWidthHeightType(i, i2, adType);
            if (sizeByWidthHeightType != null) {
                setSizes(sizeByWidthHeightType);
                loadAd(dTBAdCallback);
                return;
            }
            throw new DTBLoadException("Slot group does not contain required size of a given type");
        }
        throw new DTBLoadException("Slot group is not found");
    }

    @Override // com.amazon.device.ads.DTBAdLoader
    public void loadAd(DTBAdCallback dTBAdCallback) throws JSONException {
        try {
            this.startLoadAdTime = System.currentTimeMillis();
            this.callback = dTBAdCallback;
            if (this.adSizes.size() > 0) {
                if (this.requestHasBeenUsed) {
                    DtbLog.error(LOG_TAG, "This ad request object is already used for loading an ad. Please create a new instance to load the Ad.");
                    return;
                }
                this.requestHasBeenUsed = true;
                if (DTBMetricsConfiguration.getInstance().isFeatureEnabled("clear_aaxHostName")) {
                    removeAaxHostNameFromSharedPreferences();
                }
                DtbDeviceRegistration.verifyRegistration();
                for (DTBAdSize dTBAdSize : this.adSizes) {
                    this.sizeSlotUUIDMap.put(dTBAdSize.getWidth() + "x" + dTBAdSize.getHeight(), dTBAdSize.getSlotUUID());
                }
                try {
                    if (this.mHandlerThread == null && this.isAutoRefresh && this.refreshDuration > 0) {
                        HandlerThread handlerThread = new HandlerThread("DtbHandlerThread");
                        this.mHandlerThread = handlerThread;
                        handlerThread.start();
                        this.mHandler = new Handler(this.mHandlerThread.getLooper());
                    }
                    internalLoadAd();
                    increaseReqCount();
                    JSONObject jSONObject = new JSONObject();
                    jSONObject.put("seqCount", String.valueOf(reqCount));
                    jSONObject.put("isGdprApplicable", com.amazon.aps.ads.privacy.c.f.b());
                    com.amazon.aps.shared.a.c(jSONObject, "bidCall", String.valueOf(DtbSharedPreferences.getInstance().isValidIdfaAvailable()));
                    return;
                } catch (Exception e) {
                    com.amazon.aps.shared.a.e(1, 1, "Unknown exception occured in DTB ad call.", e);
                    return;
                }
            }
            throw new IllegalArgumentException("Please set at least one ad size in the request.");
        } catch (RuntimeException e2) {
            com.amazon.aps.shared.a.e(1, 1, "Fail to execute loadAd method", e2);
        }
    }

    public DTBAdRequest(@NonNull DTBAdNetworkInfo dTBAdNetworkInfo) {
        this.adSizes = new ArrayList();
        this.customTargets = new HashMap();
        this.sizeSlotUUIDMap = new HashMap();
        this.adError = null;
        this.requestHasBeenUsed = false;
        this.submitMetrics = true;
        this.isAutoRefresh = false;
        this.refreshFlag = false;
        this.refreshDuration = 0;
        this.mRefreshRunnable = new j(this, 0);
        this.slotGroup = null;
        this.correlationId = UUID.randomUUID().toString() + UUID.randomUUID().toString();
        try {
            if (!AdRegistration.isInitialized()) {
                DtbLog.warn("mDTB was not initialized, please use AdRegistration.getInstance(...) before using other SDK calls");
                return;
            }
            if (this.context == null) {
                this.context = AdRegistration.getContext();
            }
            setNetworkInfo(dTBAdNetworkInfo);
            if (mRaidDefined) {
                return;
            }
            defineMraid();
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, "Fail to initialize DTBAdRequest class", e);
        }
    }

    public DTBAdRequest(DTBAdRequest dTBAdRequest) {
        ArrayList arrayList = new ArrayList();
        this.adSizes = arrayList;
        HashMap map = new HashMap();
        this.customTargets = map;
        HashMap map2 = new HashMap();
        this.sizeSlotUUIDMap = map2;
        this.adError = null;
        this.requestHasBeenUsed = false;
        this.submitMetrics = true;
        this.isAutoRefresh = false;
        this.refreshFlag = false;
        this.refreshDuration = 0;
        this.mRefreshRunnable = new j(this, 0);
        this.slotGroup = null;
        this.correlationId = UUID.randomUUID().toString() + UUID.randomUUID().toString();
        arrayList.addAll(dTBAdRequest.adSizes);
        map.putAll(dTBAdRequest.customTargets);
        map2.putAll(dTBAdRequest.sizeSlotUUIDMap);
        this.adResponse = dTBAdRequest.adResponse;
        this.callback = dTBAdRequest.callback;
        this.context = dTBAdRequest.context;
        this.adError = dTBAdRequest.adError;
        this.requestHasBeenUsed = dTBAdRequest.requestHasBeenUsed;
        this.submitMetrics = dTBAdRequest.submitMetrics;
        this.isAutoRefresh = dTBAdRequest.isAutoRefresh;
        this.refreshFlag = dTBAdRequest.refreshFlag;
        this.refreshDuration = dTBAdRequest.refreshDuration;
        this.mHandler = dTBAdRequest.mHandler;
        this.mHandlerThread = dTBAdRequest.mHandlerThread;
        this.slotGroup = dTBAdRequest.slotGroup;
        setNetworkInfo(dTBAdRequest.adNetworkInfo);
    }

    public DTBAdRequest(DTBAdRequest dTBAdRequest, String str) {
        this.adSizes = new ArrayList();
        this.customTargets = new HashMap();
        this.sizeSlotUUIDMap = new HashMap();
        this.adError = null;
        this.requestHasBeenUsed = false;
        this.submitMetrics = true;
        this.isAutoRefresh = false;
        this.refreshFlag = false;
        this.refreshDuration = 0;
        this.mRefreshRunnable = new j(this, 0);
        this.slotGroup = null;
        this.correlationId = UUID.randomUUID().toString() + UUID.randomUUID().toString();
        setAdSizes(dTBAdRequest.getAdSizes());
        setSlotGroup(dTBAdRequest.getSlotGroupName());
        setCustomTargets(dTBAdRequest.getCustomTargets());
        setNetworkInfo(dTBAdRequest.adNetworkInfo);
    }
}
