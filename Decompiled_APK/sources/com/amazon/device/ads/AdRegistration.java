package com.amazon.device.ads;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.util.DisplayMetrics;
import android.webkit.WebView;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONObject;

/* loaded from: classes.dex */
public class AdRegistration {
    private static final String LOGTAG = "AdRegistration";
    private static AdRegistration adRegistrationInstance = null;
    private static CMPFlavor cmpFlavor = null;
    private static boolean consentStringDirty = false;
    private static ConsentStatus currentConsentStatus = null;
    private static String currentVendorListString = null;
    private static Map<String, String> customDictionary = null;
    private static JSONObject dsaTransparencyData = null;
    private static HashMap<String, SlotGroup> groups = null;
    private static boolean isOmSdkActivated = false;
    private static String lastSeenNonIABEncodedConsentString = null;
    private static boolean locationEnabled = false;
    private static String mAppKey = null;
    private static Context mContext = null;
    static List<String> providersProprietaryKeys = null;
    private static String sdkDistributionPlace = null;
    private static boolean testMode = false;
    private ActivityMonitor activityMonitor;
    private static Integer initCount = 0;
    static MRAIDPolicy mraidPolicy = MRAIDPolicy.AUTO_DETECT;
    static String[] serverlessMarkers = {"com.amazon.admob_adapter.APSAdMobCustomBannerEvent", "com.amazon.mopub_adapter.APSMopubCustomBannerEvent", "com.applovin.mediation.adapters.AmazonAdMarketplaceMediationAdapter"};
    private static Map<String, DTBCacheData> adMobRequestIdMap = new HashMap();
    private Set<AdProvider> providers = new HashSet();
    private EventDistributor eventDistributor = new EventDistributor();

    /* renamed from: com.amazon.device.ads.AdRegistration$1, reason: invalid class name */
    public static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$amazon$device$ads$DTBBannerType;
        static final /* synthetic */ int[] $SwitchMap$com$amazon$device$ads$DTBSlotType;

        static {
            int[] iArr = new int[DTBSlotType.values().length];
            $SwitchMap$com$amazon$device$ads$DTBSlotType = iArr;
            try {
                iArr[DTBSlotType.SLOT_320_50.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$com$amazon$device$ads$DTBSlotType[DTBSlotType.SLOT_300_250.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$com$amazon$device$ads$DTBSlotType[DTBSlotType.SLOT_728_90.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                $SwitchMap$com$amazon$device$ads$DTBSlotType[DTBSlotType.SLOT_SMART.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            int[] iArr2 = new int[DTBBannerType.values().length];
            $SwitchMap$com$amazon$device$ads$DTBBannerType = iArr2;
            try {
                iArr2[DTBBannerType.PHONE_BANNER.ordinal()] = 1;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                $SwitchMap$com$amazon$device$ads$DTBBannerType[DTBBannerType.TABLET_BANNER.ordinal()] = 2;
            } catch (NoSuchFieldError unused6) {
            }
        }
    }

    @Deprecated
    public enum CMPFlavor {
        CMP_NOT_DEFINED,
        GOOGLE_CMP,
        MOPUB_CMP,
        ADMOB_CMP
    }

    @Deprecated
    public enum ConsentStatus {
        CONSENT_NOT_DEFINED,
        EXPLICIT_YES,
        EXPLICIT_NO,
        UNKNOWN
    }

    public static class SlotGroup {
        String name;
        Set<DTBAdSize> slots;

        public SlotGroup(String str) {
            if (DtbCommonUtils.isNullOrEmpty(str)) {
                throw new IllegalArgumentException("Slot Group name cannot be null or empty");
            }
            this.name = str;
            this.slots = new HashSet();
        }

        public void addSlot(DTBAdSize dTBAdSize) {
            try {
                for (DTBAdSize dTBAdSize2 : this.slots) {
                    if (dTBAdSize2.getWidth() == dTBAdSize.getWidth() && dTBAdSize2.getHeight() == dTBAdSize.getHeight() && dTBAdSize2.getDTBAdType() == dTBAdSize.getDTBAdType()) {
                        return;
                    }
                }
                this.slots.add(dTBAdSize);
            } catch (RuntimeException e) {
                com.amazon.aps.shared.a.e(1, 1, "Fail to execute addSlot method in SlotGroup class", e);
            }
        }

        public DTBAdSize getSizeByBannerType(DTBBannerType dTBBannerType) {
            try {
                int i = AnonymousClass1.$SwitchMap$com$amazon$device$ads$DTBBannerType[dTBBannerType.ordinal()];
                if (i == 1) {
                    return getSizeByWidthAndHeight(DtbConstants.DEFAULT_PLAYER_WIDTH, 50);
                }
                if (i != 2) {
                    return null;
                }
                return getSizeByWidthAndHeight(728, 90);
            } catch (RuntimeException e) {
                com.amazon.aps.shared.a.e(2, 1, "Fail to execute getSizeByBannerType method in SlotGroup class", e);
                return null;
            }
        }

        public DTBAdSize getSizeBySlotType(DTBSlotType dTBSlotType) {
            try {
                int i = AnonymousClass1.$SwitchMap$com$amazon$device$ads$DTBSlotType[dTBSlotType.ordinal()];
                int i2 = 50;
                int i3 = DtbConstants.DEFAULT_PLAYER_WIDTH;
                if (i == 1) {
                    return getSizeByWidthAndHeight(DtbConstants.DEFAULT_PLAYER_WIDTH, 50);
                }
                if (i == 2) {
                    return getSizeByWidthAndHeight(300, 250);
                }
                if (i == 3) {
                    return getSizeByWidthAndHeight(728, 90);
                }
                if (i != 4) {
                    return null;
                }
                if (DtbDeviceDataRetriever.isTablet()) {
                    i2 = 90;
                    i3 = 728;
                }
                return getSizeByWidthAndHeight(i3, i2);
            } catch (RuntimeException e) {
                com.amazon.aps.shared.a.e(2, 1, "Fail to execute getSizeBySlotType method in SlotGroup class", e);
                return null;
            }
        }

        public DTBAdSize getSizeBySlotUUID(String str) {
            for (DTBAdSize dTBAdSize : this.slots) {
                if (dTBAdSize.getSlotUUID().equals(str)) {
                    return dTBAdSize;
                }
            }
            return null;
        }

        public DTBAdSize getSizeByWidthAndHeight(int i, int i2) {
            return getSizeByWidthHeightType(i, i2, AdType.DISPLAY);
        }

        public DTBAdSize getSizeByWidthHeightType(int i, int i2, AdType adType) {
            try {
                for (DTBAdSize dTBAdSize : this.slots) {
                    if (dTBAdSize.getHeight() == i2 && dTBAdSize.getWidth() == i && dTBAdSize.getDTBAdType() == adType) {
                        return dTBAdSize;
                    }
                }
                return null;
            } catch (RuntimeException e) {
                com.amazon.aps.shared.a.e(2, 1, "Fail to execute getSizeByWidthHeightType method in SlotGroup class", e);
                return null;
            }
        }
    }

    private AdRegistration(String str, Context context) throws IllegalArgumentException {
        if (context == null || str == null || "".equals(str.trim())) {
            IllegalArgumentException illegalArgumentException = new IllegalArgumentException("Invalid parameters for initialization. SDK initialize failed due to invalid registration parameters");
            com.amazon.aps.shared.a.e(1, 1, "Invalid parameters for initialization. SDK initialize failed due to invalid registration parameters", null);
            throw illegalArgumentException;
        }
        if (WebView.getCurrentWebViewPackage() == null) {
            com.amazon.aps.shared.a.e(1, 2, "No WebView installed on device. APS SDK failed to initialize", null);
            return;
        }
        mAppKey = str;
        Context applicationContext = context.getApplicationContext();
        mContext = applicationContext;
        com.amazon.aps.shared.a.d(applicationContext);
        String version = getVersion();
        if (version != null && !version.trim().isEmpty()) {
            com.amazon.aps.shared.a.h = version.trim();
        }
        Context context2 = mContext;
        if (context2 != null) {
            DisplayMetrics displayMetrics = new DisplayMetrics();
            String sDKFramework = DtbCommonUtils.getSDKFramework();
            String str2 = DtbDeviceDataRetriever.isTablet() ? "tablet" : "phone";
            String screenSize = DtbDeviceDataRetriever.getScreenSize(displayMetrics, DtbDeviceDataRetriever.ORIENTATION_PORTRAIT);
            String connectionType = DtbDeviceData.getConnectionType();
            int i = com.amazon.aps.ads.a.a;
            String version2 = getVersion();
            Intrinsics.checkNotNullParameter(context2, "context");
            com.amazon.aps.ads.c.b = 1;
            try {
                com.amazon.aps.shared.a.a = new com.amazon.aps.shared.metrics.model.c(sDKFramework, screenSize, str2, connectionType, null);
                com.amazon.aps.shared.a.b = new com.amazon.aps.shared.metrics.model.n(version2);
                com.amazon.aps.shared.a.g = context2;
                com.amazon.aps.shared.a.b();
            } catch (RuntimeException e) {
                com.amazon.aps.shared.a.e(1, 1, "Error in initializing the ApsMetrics", e);
            }
        }
        DtbSharedPreferences dtbSharedPreferencesCreateInstance = DtbSharedPreferences.createInstance();
        context.checkCallingOrSelfPermission("android.permission.INTERNET");
        if (context.checkCallingOrSelfPermission("android.permission.INTERNET") == -1) {
            DtbLog.error(LOGTAG, "Network task cannot commence because the INTERNET permission is missing from the app's manifest.");
        }
        String versionInUse = dtbSharedPreferencesCreateInstance.getVersionInUse();
        if (versionInUse == null || DtbCommonUtils.isNullOrEmpty(versionInUse)) {
            dtbSharedPreferencesCreateInstance.setVersionInUse(DtbConstants.SDK_VERSION);
        }
        DtbOmSdkSessionManager.activateOMSDK(mContext);
        currentConsentStatus = ConsentStatus.CONSENT_NOT_DEFINED;
        cmpFlavor = CMPFlavor.CMP_NOT_DEFINED;
        consentStringDirty = false;
        customDictionary = new HashMap();
        JSONObject jSONObjectLoadJsonFromAsset = DTBAdUtil.loadJsonFromAsset("aps_distribution_marker.json");
        if (jSONObjectLoadJsonFromAsset != null) {
            try {
                sdkDistributionPlace = jSONObjectLoadJsonFromAsset.getString("distribution");
            } catch (Exception unused) {
                DtbLog.warn("Unable to get distribution place value");
            }
        }
    }

    public static void addAdMobCache(String str, DTBCacheData dTBCacheData) {
        if (adMobRequestIdMap == null) {
            adMobRequestIdMap = new HashMap();
        }
        removeExpiredAdMobCache();
        synchronized (adMobRequestIdMap) {
            adMobRequestIdMap.put(str, dTBCacheData);
        }
    }

    public static void addCustomAttribute(String str, String str2) {
        if (!isInitialized()) {
            synchronized (com.amazon.aps.ads.d.class) {
            }
            throw new IllegalStateException("mDTB was not initialized, please use AdRegistration.getInstance(...) before using other SDK calls");
        }
        try {
            if (customDictionary == null) {
                customDictionary = new HashMap();
            }
            customDictionary.put(str, str2);
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute addCustomAttribute method", e);
        }
    }

    public static void addProvider(AdProvider adProvider) {
        if (adRegistrationInstance == null) {
            throw new IllegalStateException("Instance must be initialized prior to adding providers");
        }
        Class<?> cls = adProvider.getClass();
        Iterator<AdProvider> it2 = adRegistrationInstance.providers.iterator();
        while (it2.hasNext()) {
            if (it2.next().getClass().equals(cls)) {
                return;
            }
        }
        adRegistrationInstance.providers.add(adProvider);
        appendProprietaryProviderKeys(adProvider.getProprietaryKeys());
    }

    public static void addSlotGroup(SlotGroup slotGroup) {
        try {
            if (groups == null) {
                groups = new HashMap<>();
            }
            groups.put(slotGroup.name, slotGroup);
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, "Fail to execute addSlotGroup method", e);
        }
    }

    public static void appendProprietaryProviderKeys(String[] strArr) {
        if (providersProprietaryKeys == null) {
            providersProprietaryKeys = new ArrayList();
        }
        for (String str : strArr) {
            providersProprietaryKeys.add(str);
        }
    }

    public static void enableLogging(boolean z) {
        try {
            if (z) {
                DTBLogLevel dTBLogLevel = DTBLogLevel.All;
                DtbLog.setLogLevel(dTBLogLevel);
                com.amazon.aps.ads.c.b = AbstractC0147y.n(8)[dTBLogLevel.intValue()];
            } else {
                DTBLogLevel dTBLogLevel2 = DTBLogLevel.Error;
                DtbLog.setLogLevel(dTBLogLevel2);
                com.amazon.aps.ads.c.b = AbstractC0147y.n(8)[dTBLogLevel2.intValue()];
            }
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute enableLogging method", e);
        }
    }

    public static void enableTesting(boolean z) {
        try {
            if (!z) {
                testMode = false;
            } else {
                if (DTBAdUtil.isInstalledFromAppStore(mContext)) {
                    return;
                }
                testMode = z;
                DtbLog.enableCallerInfo(z);
            }
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute enableTesting method", e);
        }
    }

    private ActivityMonitor getActivityMonitor() {
        return this.activityMonitor;
    }

    public static DTBCacheData getAdMobCache(String str) {
        if (DtbCommonUtils.isNullOrEmpty(str) || adMobRequestIdMap == null) {
            return null;
        }
        removeExpiredAdMobCache();
        return adMobRequestIdMap.get(str);
    }

    public static Map<String, DTBCacheData> getAdMobCacheData() {
        return adMobRequestIdMap;
    }

    public static Set<AdProvider> getAdProviders() {
        AdRegistration adRegistration = adRegistrationInstance;
        if (adRegistration != null) {
            return adRegistration.providers;
        }
        return null;
    }

    public static String getAppKey() {
        return mAppKey;
    }

    public static CMPFlavor getCMPFlavor() {
        if (!isInitialized()) {
            throw new IllegalStateException("mDTB was not initialized, please use AdRegistration.getInstance(...) before using other SDK calls");
        }
        String cMPFlavor = DtbSharedPreferences.getInstance().getCMPFlavor();
        return cMPFlavor == null ? cmpFlavor : CMPFlavor.valueOf(cMPFlavor);
    }

    public static ConsentStatus getConsentStatus() {
        if (!isInitialized()) {
            throw new IllegalStateException("mDTB was not initialized, please use AdRegistration.getInstance(...) before using other SDK calls");
        }
        String consentStatus = DtbSharedPreferences.getInstance().getConsentStatus();
        return consentStatus == null ? currentConsentStatus : ConsentStatus.valueOf(consentStatus);
    }

    public static Context getContext() {
        return mContext;
    }

    public static Activity getCurrentActivity() {
        return adRegistrationInstance.getActivityMonitor().getCurrentActivity();
    }

    public static Map<String, String> getCustomDictionary() {
        return customDictionary;
    }

    public static JSONObject getDsaTransparencyData() {
        return dsaTransparencyData;
    }

    public static String getEncodedNonIABString() {
        String encodedNonIABConsentString;
        if (!consentStringDirty) {
            return lastSeenNonIABEncodedConsentString;
        }
        String vendorList = DtbSharedPreferences.getInstance().getVendorList();
        String consentStatus = DtbSharedPreferences.getInstance().getConsentStatus();
        String cMPFlavor = DtbSharedPreferences.getInstance().getCMPFlavor();
        if (vendorList == null && consentStatus == null && cMPFlavor == null) {
            encodedNonIABConsentString = "";
        } else {
            encodedNonIABConsentString = DTBGDPREncoder.getEncodedNonIABConsentString(getVendorListFromString(vendorList));
            if (!DtbCommonUtils.isNullOrEmpty(encodedNonIABConsentString)) {
                DtbSharedPreferences.getInstance().saveNonIABCustomConsent(encodedNonIABConsentString);
            }
        }
        consentStringDirty = false;
        lastSeenNonIABEncodedConsentString = encodedNonIABConsentString;
        return encodedNonIABConsentString;
    }

    @Deprecated
    public static EventDistributor getEventDistributer() {
        AdRegistration adRegistration = adRegistrationInstance;
        if (adRegistration != null) {
            return adRegistration.eventDistributor;
        }
        throw new IllegalStateException("Instance must be initialized prior using getEventDistributer API");
    }

    public static AdRegistration getInstance(@NonNull String str, @NonNull Context context) throws IllegalArgumentException {
        Boolean boolValueOf;
        if (DtbCommonUtils.isNullOrEmpty(str) || context == null) {
            synchronized (com.amazon.aps.ads.d.class) {
            }
            com.amazon.aps.shared.a.c(null, "initCallFailed", str);
        }
        if (!isInitialized()) {
            com.amazon.aps.ads.privacy.c cVar = com.amazon.aps.ads.privacy.c.f;
            if (!cVar.b && context != null) {
                SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
                if (prefs != null) {
                    Intrinsics.checkNotNullParameter(prefs, "prefs");
                    String strA = cVar.a(prefs);
                    com.amazon.aps.ads.privacy.a aVar = cVar.c;
                    aVar.a(strA);
                    Intrinsics.checkNotNullParameter(prefs, "prefs");
                    Intrinsics.checkNotNullParameter("IABTCF_gdprApplies", "key");
                    try {
                    } catch (Exception e) {
                        Intrinsics.checkNotNullParameter(cVar, "<this>");
                        com.amazon.aps.shared.a.e(1, 1, "Error reading the shared pref value", e);
                    }
                    Integer numValueOf = prefs.contains("IABTCF_gdprApplies") ? Integer.valueOf(prefs.getInt("IABTCF_gdprApplies", 0)) : null;
                    if (numValueOf != null) {
                        boolValueOf = Boolean.valueOf(numValueOf.intValue() == 1);
                    } else {
                        boolValueOf = null;
                    }
                    aVar.d = boolValueOf;
                    cVar.d();
                    prefs.registerOnSharedPreferenceChangeListener(cVar.e);
                }
                cVar.b = true;
            }
            adRegistrationInstance = new AdRegistration(str, context);
            com.amazon.aps.ads.privacy.c.f.d();
            DTBMetricsConfiguration.getInstance();
            if (DTBMetricsConfiguration.getInstance().isFeatureEnabled(DTBMetricsConfiguration.FEATURE_CONFIG_IN_INIT)) {
                DtbDeviceRegistration.verifyRegistration();
            }
        } else if (str != null && !str.equals(mAppKey)) {
            mAppKey = str;
            DtbSharedPreferences.createInstance();
        }
        adRegistrationInstance.setActivityMonitor(new ActivityMonitor(context));
        synchronized (com.amazon.aps.ads.d.class) {
        }
        Integer numValueOf2 = Integer.valueOf(initCount.intValue() + 1);
        initCount = numValueOf2;
        com.amazon.aps.shared.a.c(null, "initCall", String.valueOf(numValueOf2));
        return adRegistrationInstance;
    }

    public static MRAIDPolicy getMRAIDPolicy() {
        return mraidPolicy;
    }

    public static List<String> getProprietaryProviderKeys() {
        if (providersProprietaryKeys == null) {
            providersProprietaryKeys = new ArrayList();
        }
        return providersProprietaryKeys;
    }

    public static String getSDKDistributionPlace() {
        return sdkDistributionPlace;
    }

    public static String[] getServerlessMarkers() {
        return serverlessMarkers;
    }

    public static SlotGroup getSlotGroup(String str) {
        if (str == null) {
            return null;
        }
        try {
            HashMap<String, SlotGroup> map = groups;
            if (map != null) {
                return map.get(str);
            }
            return null;
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute getSlotGroup method", e);
            return null;
        }
    }

    private static String getStringFromVendorList(List<Integer> list) {
        return list.toString();
    }

    private static List<Integer> getVendorListFromString(String str) {
        ArrayList arrayList = new ArrayList();
        if (str != null && str.length() > 2) {
            for (String str2 : str.substring(1, str.length() - 1).split(",")) {
                arrayList.add(Integer.valueOf(Integer.parseInt(str2.trim())));
            }
        }
        return arrayList;
    }

    public static String getVersion() {
        return DtbCommonUtils.getSDKVersion();
    }

    public static boolean hasAdapters() throws ClassNotFoundException {
        for (String str : serverlessMarkers) {
            try {
                Class.forName(str);
                return true;
            } catch (Exception unused) {
            }
        }
        return false;
    }

    @Deprecated
    public static boolean isConsentStatusUnknown() {
        try {
            if (currentConsentStatus != ConsentStatus.CONSENT_NOT_DEFINED && currentConsentStatus != ConsentStatus.UNKNOWN) {
                if (DtbSharedPreferences.getInstance().getVendorList() != null) {
                    return false;
                }
            }
            return true;
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute isConsentStatusUnknown method", e);
            return true;
        }
    }

    public static boolean isInitialized() {
        return adRegistrationInstance != null;
    }

    public static boolean isLocationEnabled() {
        return locationEnabled;
    }

    public static boolean isTestMode() {
        return testMode;
    }

    public static void removeAdMobCache(String str) {
        Map<String, DTBCacheData> map = adMobRequestIdMap;
        if (map != null) {
            synchronized (map) {
                adMobRequestIdMap.remove(str);
            }
        }
    }

    public static void removeCustomAttribute(String str) {
        if (!isInitialized()) {
            synchronized (com.amazon.aps.ads.d.class) {
            }
            throw new IllegalStateException("mDTB was not initialized, please use AdRegistration.getInstance(...) before using other SDK calls");
        }
        try {
            if (DtbCommonUtils.isNullOrEmpty(customDictionary)) {
                return;
            }
            customDictionary.remove(str);
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute removeCustomAttribute method", e);
        }
    }

    public static void removeExpiredAdMobCache() {
        Map<String, DTBCacheData> map = adMobRequestIdMap;
        if (map != null) {
            synchronized (map) {
                try {
                    long time = new Date().getTime();
                    Iterator<Map.Entry<String, DTBCacheData>> it2 = adMobRequestIdMap.entrySet().iterator();
                    while (it2.hasNext()) {
                        if (time - it2.next().getValue().getResponseTimeStamp() > 29000) {
                            it2.remove();
                        }
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
    }

    @Deprecated
    public static void resetNonIAB() {
        try {
            DtbSharedPreferences.getInstance().removeCMPFlavor();
            DtbSharedPreferences.getInstance().removeConsentStatus();
            DtbSharedPreferences.getInstance().removeVendorList();
            DtbSharedPreferences.getInstance().removeNonIABCustomConsent();
            currentVendorListString = null;
            currentConsentStatus = ConsentStatus.CONSENT_NOT_DEFINED;
            cmpFlavor = CMPFlavor.CMP_NOT_DEFINED;
            consentStringDirty = false;
            lastSeenNonIABEncodedConsentString = null;
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute resetNonIAB method", e);
        }
    }

    private void setActivityMonitor(ActivityMonitor activityMonitor) {
        this.activityMonitor = activityMonitor;
    }

    @Deprecated
    public static void setAppKey(@NonNull String str) throws IllegalArgumentException {
        if (!isInitialized()) {
            throw new IllegalStateException("mDTB was not initialized, please use AdRegistration.getInstance(...) before using other SDK calls");
        }
        if (DtbCommonUtils.isNullOrEmpty(str)) {
            IllegalArgumentException illegalArgumentException = new IllegalArgumentException("Invalid parameters:appKey for initialization.");
            DtbLog.fatal(LOGTAG, "mDTB SDK initialize failed due to invalid registration parameter:appKey.", illegalArgumentException);
            throw illegalArgumentException;
        }
        mAppKey = str;
        DtbSharedPreferences.createInstance();
    }

    @Deprecated
    public static void setCMPFlavor(CMPFlavor cMPFlavor) {
        if (!isInitialized()) {
            throw new IllegalStateException("mDTB was not initialized, please use AdRegistration.getInstance(...) before using other SDK calls");
        }
        try {
            if (cMPFlavor == CMPFlavor.CMP_NOT_DEFINED) {
                DtbLog.error(LOGTAG, "Set cmp type failed due to invalid cmp type parameters. Not allowed to set cmp type to not defined.");
                return;
            }
            CMPFlavor cMPFlavor2 = cmpFlavor;
            if (cMPFlavor2 == null || cMPFlavor2 != cMPFlavor) {
                consentStringDirty = true;
                cmpFlavor = cMPFlavor;
                DtbSharedPreferences.getInstance().saveCMPFlavor(cMPFlavor.name());
            }
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute setCMPFlavor method", e);
        }
    }

    @Deprecated
    public static void setConsentStatus(ConsentStatus consentStatus) {
        if (!isInitialized()) {
            throw new IllegalStateException("mDTB was not initialized, please use AdRegistration.getInstance(...) before using other SDK calls");
        }
        try {
            if (consentStatus == ConsentStatus.CONSENT_NOT_DEFINED) {
                DtbLog.error(LOGTAG, "Set consent status failed due to invalid consent status parameters. Not allowed to set consent not defined.");
                return;
            }
            ConsentStatus consentStatus2 = currentConsentStatus;
            if (consentStatus2 == null || consentStatus2 != consentStatus) {
                consentStringDirty = true;
                currentConsentStatus = consentStatus;
                DtbSharedPreferences.getInstance().saveConsentStatus(consentStatus.name());
            }
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute setConsentStatus method", e);
        }
    }

    @Deprecated
    public static void setContext(Context context) {
        if (context != null) {
            mContext = context.getApplicationContext();
        } else {
            IllegalArgumentException illegalArgumentException = new IllegalArgumentException("Invalid parameters:context for initialization.");
            DtbLog.fatal(LOGTAG, "mDTB SDK initialize failed due to invalid registration parameter:context.", illegalArgumentException);
            throw illegalArgumentException;
        }
    }

    public static void setDsaTransparency(JSONObject jSONObject) {
        dsaTransparencyData = jSONObject;
    }

    public static void setMRAIDPolicy(MRAIDPolicy mRAIDPolicy) {
        mraidPolicy = mRAIDPolicy;
        DTBAdRequest.resetMraid();
    }

    public static void setMRAIDSupportedVersions(String[] strArr) {
        DTBAdRequest.setMRAIDSupportedVersions(strArr);
    }

    @Deprecated
    public static void setServerlessMarkers(String[] strArr) {
        serverlessMarkers = strArr;
    }

    @Deprecated
    public static void setVendorList(List<Integer> list) {
        if (!isInitialized()) {
            throw new IllegalStateException("mDTB was not initialized, please use AdRegistration.getInstance(...) before using other SDK calls");
        }
        try {
            if (list == null) {
                DtbLog.error(LOGTAG, "Set vendor list failed due to invalid vendor list parameters with value null.");
                return;
            }
            String stringFromVendorList = getStringFromVendorList(list);
            String str = currentVendorListString;
            if (str == null || !str.equals(stringFromVendorList)) {
                consentStringDirty = true;
                currentVendorListString = stringFromVendorList;
                DtbSharedPreferences.getInstance().saveVendorList(stringFromVendorList);
            }
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute setVendorList method", e);
        }
    }

    public static void useGeoLocation(boolean z) {
        locationEnabled = z;
    }

    public static void enableLogging(boolean z, DTBLogLevel dTBLogLevel) {
        try {
            if (z) {
                DtbLog.setLogLevel(dTBLogLevel);
                com.amazon.aps.ads.c.b = AbstractC0147y.n(8)[dTBLogLevel.intValue()];
            } else {
                DtbLog.setLogLevel(DTBLogLevel.Error);
            }
        } catch (RuntimeException e) {
            DtbLog.error(LOGTAG, "Fail to execute enableLogging method with logLevel argument");
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute enableLogging method with logLevel argument", e);
        }
    }
}
