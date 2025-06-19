package com.amazon.device.ads;

import android.content.SharedPreferences;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Set;
import kotlin.jvm.internal.C4943b;
import kotlin.jvm.internal.C4952k;
import kotlin.jvm.internal.C4957p;
import kotlin.jvm.internal.C4959s;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.N;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public class DtbSharedPreferences {
    private static final String AAX_HOSTNAME_PREF_NAME = "amzn-dtb-ad-aax-hostname";
    private static final String AAX_VIDEO_HOSTNAME_PREF_NAME = "amzn-dtb-ad-aax-video-hostname";
    private static final String ADID_PREF_NAME = "amzn-dtb-ad-id";
    private static final String BID_TIMEOUT_PREF_NAME = "amzn-dtb-bid-timeout";
    private static final String CONFIG_LAST_CHECKIN_PREF_NAME = "amzn-dtb-ad-config-last-checkin";
    private static final String CONFIG_TTL_PREF_NAME = "amzn-dtb-ad-config-ttl";
    private static final String DTB_VERSION_IN_USE = "amzn-dtb-version_in_use";
    private static final String ENCODED_PRICE_CHECK_PREF_NAME = "amzn-dtb-enable-encoded-price-check";
    private static final String IDFA_PREF_NAME = "amzn-dtb-idfa";
    private static final String IS_ADID_CHANGED_PREF_NAME = "amzn-dtb-adid-changed";
    private static final String IS_ADID_NEW_PREF_NAME = "amzn-dtb-adid-new";
    private static final String IS_GPS_UNAVAILABLE_PREF_NAME = "amzn-dtb-is-gps-unavailable";
    private static final String LOG_TAG = "DtbSharedPreferences";
    private static final String NON_IAB_CMP_FLAVOR = "NON_IAB_CMP_FLAVOR";
    private static final String NON_IAB_CONSENT_STATUS = "NON_IAB_CONSENT_STATUS";
    private static final String NON_IAB_CUSTOM_CONSENT = "NON_IAB_Custom_Consent";
    private static final String NON_IAB_VENDORLIST = "NON_IAB_VENDORLIST";
    private static final String OO_PREF_NAME = "amzn-dtb-oo";
    private static final String PJ_TEMPLATE_PREF_NAME = "amzn-dtb-pj-template";
    private static final String PREF_FILE_NAME = "com.amazon.device.ads.dtb.preferences";
    private static final String PRIVACY_LOCATION_ACCURACY_IN_METERS_PREF_NAME = "amzn-dtb-privacy-location-accuracy-in-meters";
    private static final String PRIVACY_LOCATION_MODE_PREF_NAME = "amzn-dtb-privacy-location-mode";
    private static final String SDK_WRAPPER_PING = "sdk-wrapper-ping";
    private static final String SIS_ENDPOINT_PREF_NAME = "amzn-dtb-ad-sis-endpoint";
    private static final String SIS_LAST_CHECKIN_PREF_NAME = "amzn-dtb-ad-sis-last-checkin";
    private static final String SIS_LAST_PING_PREF_NAME = "amzn-dtb-ad-sis-last-ping";
    private static final String SIS_LAST_PING_WEB_RESOURCES = "amzn-dtb-web-resource-ping";
    public static DtbSharedPreferences dtbSharedPreferencesInstance;
    private static SharedPreferences sharedPreferences;
    private static com.amazon.aps.ads.util.a apsInMemoryManager = com.amazon.aps.ads.util.a.b;
    private static boolean isIgnore = false;
    private static boolean IS_SIS_REGISTERATION_SUCCESSFUL = false;

    public DtbSharedPreferences() {
        if (AdRegistration.getContext() != null) {
            sharedPreferences = AdRegistration.getContext().getSharedPreferences(PREF_FILE_NAME, 0);
        }
    }

    public static void clearStorage() {
        com.amazon.aps.ads.c.a();
        try {
            if (getSharedPreferences() != null) {
                getSharedPreferences().edit().clear().commit();
            }
            flushPreference(IDFA_PREF_NAME);
        } catch (Exception e) {
            com.amazon.aps.ads.c.b("APSAndroidShared", "Error in clearing the storage:" + e.getMessage());
        }
    }

    private static boolean containsPreference(String key) {
        boolean zContainsKey;
        com.amazon.aps.ads.util.a aVar = apsInMemoryManager;
        synchronized (aVar) {
            Intrinsics.checkNotNullParameter(key, "key");
            zContainsKey = aVar.a.containsKey(key);
        }
        if (zContainsKey) {
            return true;
        }
        if (com.amazon.aps.ads.privacy.c.f.c()) {
            return getSharedPreferences().contains(key);
        }
        return false;
    }

    public static DtbSharedPreferences createInstance() {
        DtbSharedPreferences dtbSharedPreferences = new DtbSharedPreferences();
        dtbSharedPreferencesInstance = dtbSharedPreferences;
        return dtbSharedPreferences;
    }

    private static void flushPreference(String key) {
        if (com.amazon.aps.ads.privacy.c.f.c()) {
            SharedPreferences sharedPreferences2 = getSharedPreferences();
            if (sharedPreferences2.contains(key)) {
                SharedPreferences.Editor editorEdit = sharedPreferences2.edit();
                editorEdit.remove(key);
                editorEdit.apply();
            }
        }
        com.amazon.aps.ads.util.a aVar = apsInMemoryManager;
        synchronized (aVar) {
            Intrinsics.checkNotNullParameter(key, "key");
            if (aVar.a.containsKey(key)) {
                aVar.a.remove(key);
            }
        }
    }

    public static DtbSharedPreferences getInstance() {
        if (dtbSharedPreferencesInstance == null) {
            createInstance();
        }
        return dtbSharedPreferencesInstance;
    }

    private static <T> T getPref(String key, Class<T> clazz) {
        boolean zContainsKey;
        T t = (T) null;
        if (isIgnore) {
            return null;
        }
        com.amazon.aps.ads.util.a aVar = apsInMemoryManager;
        synchronized (aVar) {
            Intrinsics.checkNotNullParameter(key, "key");
            zContainsKey = aVar.a.containsKey(key);
        }
        if (!zContainsKey) {
            com.amazon.aps.ads.util.a aVar2 = apsInMemoryManager;
            Object prefFromSys = getPrefFromSys(key, clazz);
            synchronized (aVar2) {
                Intrinsics.checkNotNullParameter(key, "key");
                if (prefFromSys != null) {
                    aVar2.a.put(key, prefFromSys);
                }
            }
        }
        com.amazon.aps.ads.util.a aVar3 = apsInMemoryManager;
        synchronized (aVar3) {
            Intrinsics.checkNotNullParameter(key, "key");
            Intrinsics.checkNotNullParameter(clazz, "clazz");
            if (aVar3.a.containsKey(key)) {
                return (T) aVar3.a(clazz, key);
            }
            if (!clazz.isAssignableFrom(String.class) && !clazz.isAssignableFrom(Set.class) && !clazz.isAssignableFrom(N.a.getClass()) && !clazz.equals(String.class)) {
                if (clazz.isAssignableFrom(Boolean.TYPE) || clazz.isAssignableFrom(C4943b.a.getClass()) || clazz.equals(Boolean.class)) {
                    t = (T) Boolean.FALSE;
                } else if (clazz.isAssignableFrom(Long.TYPE) || clazz.isAssignableFrom(C4959s.a.getClass()) || clazz.equals(Long.class)) {
                    t = (T) 0L;
                } else if (clazz.isAssignableFrom(Integer.TYPE) || clazz.isAssignableFrom(C4957p.a.getClass()) || clazz.equals(Integer.class)) {
                    t = (T) 0;
                } else if (clazz.isAssignableFrom(Float.TYPE) || clazz.isAssignableFrom(C4952k.a.getClass()) || clazz.equals(Float.class)) {
                    t = (T) Float.valueOf(DefinitionKt.NO_Float_VALUE);
                }
            }
            return t;
        }
    }

    private static <T> T getPrefFromSys(String str, Class<T> cls) {
        if (isIgnore || !com.amazon.aps.ads.privacy.c.f.c()) {
            return null;
        }
        SharedPreferences sharedPreferences2 = getSharedPreferences();
        if (cls.isAssignableFrom(String.class)) {
            return (T) sharedPreferences2.getString(str, null);
        }
        if (cls.isAssignableFrom(Set.class)) {
            return (T) sharedPreferences2.getStringSet(str, null);
        }
        if (cls.isAssignableFrom(Boolean.class)) {
            return (T) Boolean.valueOf(sharedPreferences2.getBoolean(str, false));
        }
        if (cls.isAssignableFrom(Long.class)) {
            return (T) Long.valueOf(sharedPreferences2.getLong(str, 0L));
        }
        if (cls.isAssignableFrom(Integer.class)) {
            return (T) Integer.valueOf(sharedPreferences2.getInt(str, 0));
        }
        if (cls.isAssignableFrom(Float.class)) {
            return (T) Float.valueOf(sharedPreferences2.getFloat(str, DefinitionKt.NO_Float_VALUE));
        }
        throw new IllegalArgumentException(cls.getName().concat(" is not supported"));
    }

    private static SharedPreferences getSharedPreferences() {
        if (sharedPreferences == null) {
            sharedPreferences = AdRegistration.getContext().getSharedPreferences(PREF_FILE_NAME, 0);
        }
        return sharedPreferences;
    }

    private void saveHostName(String str, String str2) {
        if (DtbCommonUtils.isNullOrEmpty(str)) {
            savePref(str2, DtbConstants.AAX_HOSTNAME);
        } else {
            savePref(str2, str);
        }
    }

    private static <T> void savePref(String key, T t) {
        if (isIgnore) {
            return;
        }
        com.amazon.aps.ads.util.a aVar = apsInMemoryManager;
        synchronized (aVar) {
            Intrinsics.checkNotNullParameter(key, "key");
            if (t != null) {
                aVar.a.put(key, t);
            }
        }
        savePrefInSys(key, t);
    }

    /* JADX WARN: Multi-variable type inference failed */
    private static <T> void savePrefInSys(String str, T t) {
        SharedPreferences sharedPreferences2;
        if (isIgnore || !com.amazon.aps.ads.privacy.c.f.c() || (sharedPreferences2 = getSharedPreferences()) == null) {
            return;
        }
        SharedPreferences.Editor editorEdit = sharedPreferences2.edit();
        if (t instanceof Boolean) {
            editorEdit.putBoolean(str, ((Boolean) t).booleanValue());
        } else if (t instanceof String) {
            editorEdit.putString(str, (String) t);
        } else if (t instanceof Integer) {
            editorEdit.putInt(str, ((Integer) t).intValue());
        } else if (t instanceof Float) {
            editorEdit.putFloat(str, ((Float) t).floatValue());
        } else if (t instanceof Long) {
            editorEdit.putLong(str, ((Long) t).longValue());
        } else {
            if (!(t instanceof Set)) {
                throw new IllegalArgumentException("Saving of " + t.getClass() + " is not supported.");
            }
            editorEdit.putStringSet(str, (Set) t);
        }
        editorEdit.apply();
    }

    public static void setIgnoreMode() {
        isIgnore = true;
    }

    public String getAaxHostname() {
        String str = (String) getPref(AAX_HOSTNAME_PREF_NAME, String.class);
        if (!AdRegistration.isTestMode() || !DtbDebugProperties.isInternalDebugMode) {
            return DtbCommonUtils.isNullOrEmpty(str) ? DtbConstants.AAX_HOSTNAME : str;
        }
        if (str == null) {
            str = DtbConstants.AAX_HOSTNAME;
        }
        return DtbDebugProperties.getAaxHostName(str);
    }

    public String getAaxVideoHostName() {
        return (String) getPref(AAX_VIDEO_HOSTNAME_PREF_NAME, String.class);
    }

    public String getAdId() {
        return (String) getPref(ADID_PREF_NAME, String.class);
    }

    public int getBidTimeout() {
        Integer num = (Integer) getPref(BID_TIMEOUT_PREF_NAME, Integer.class);
        if (num == null || num.intValue() == 0) {
            return 5000;
        }
        return num.intValue();
    }

    public String getCMPFlavor() {
        return (String) getPref(NON_IAB_CMP_FLAVOR, String.class);
    }

    public Long getConfigLastCheckIn() {
        long jLongValue = ((Long) getPref(CONFIG_LAST_CHECKIN_PREF_NAME, Long.class)).longValue();
        if (jLongValue <= 0) {
            jLongValue = getSisLastCheckIn().longValue();
        }
        return Long.valueOf(jLongValue);
    }

    public synchronized long getConfigTtlInMilliSeconds() {
        long jLongValue = ((Long) getPref(CONFIG_TTL_PREF_NAME, Long.class)).longValue();
        if (jLongValue < 900000) {
            return 172800000L;
        }
        return jLongValue;
    }

    public String getConsentStatus() {
        return (String) getPref(NON_IAB_CONSENT_STATUS, String.class);
    }

    public String getIdfa() {
        return (String) getPref(IDFA_PREF_NAME, String.class);
    }

    public boolean getIsAdIdChanged() {
        return ((Boolean) getPref(IS_ADID_CHANGED_PREF_NAME, Boolean.class)).booleanValue();
    }

    public boolean getIsAdIdNew() {
        return ((Boolean) getPref(IS_ADID_NEW_PREF_NAME, Boolean.class)).booleanValue();
    }

    public boolean getIsSisRegisterationSuccessful() {
        return IS_SIS_REGISTERATION_SUCCESSFUL;
    }

    public String getNonIABCustomConsent() {
        return (String) getPref(NON_IAB_CUSTOM_CONSENT, String.class);
    }

    public synchronized Boolean getOptOut() {
        if (!containsPreference(OO_PREF_NAME)) {
            return null;
        }
        return (Boolean) getPref(OO_PREF_NAME, Boolean.class);
    }

    public JSONObject getPJTemplate() {
        try {
            return new JSONObject((String) getPref(PJ_TEMPLATE_PREF_NAME, String.class));
        } catch (Exception unused) {
            JSONObject jSONObject = new JSONObject();
            DtbLog.warn(LOG_TAG, "Get Pj template failed when fetching from Cache");
            return jSONObject;
        }
    }

    public synchronized float getPrivacyLocationConfigAccuracyInMeters() {
        Float f = (Float) getPref(PRIVACY_LOCATION_ACCURACY_IN_METERS_PREF_NAME, Float.class);
        if (f == null) {
            return Float.MAX_VALUE;
        }
        return f.floatValue();
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x0037  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x003a  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0041 A[Catch: all -> 0x002b, TRY_ENTER, TRY_LEAVE, TryCatch #0 {all -> 0x002b, blocks: (B:3:0x0001, B:5:0x0011, B:22:0x003d, B:25:0x0041, B:10:0x0021, B:15:0x002d, B:28:0x0045), top: B:33:0x0001 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public synchronized com.amazon.device.ads.PrivacyLocationMode getPrivacyLocationConfigMode() {
        /*
            r4 = this;
            monitor-enter(r4)
            java.lang.String r0 = "amzn-dtb-privacy-location-mode"
            java.lang.Class<java.lang.String> r1 = java.lang.String.class
            java.lang.Object r0 = getPref(r0, r1)     // Catch: java.lang.Throwable -> L2b
            java.lang.String r0 = (java.lang.String) r0     // Catch: java.lang.Throwable -> L2b
            boolean r1 = com.amazon.device.ads.DtbCommonUtils.isNullOrEmpty(r0)     // Catch: java.lang.Throwable -> L2b
            if (r1 != 0) goto L45
            int r1 = r0.hashCode()     // Catch: java.lang.Throwable -> L2b
            r2 = -1679810537(0xffffffff9be02017, float:-3.707843E-22)
            r3 = 1
            if (r1 == r2) goto L2d
            r2 = 67893076(0x40bf754, float:1.6452939E-36)
            if (r1 == r2) goto L21
            goto L37
        L21:
            java.lang.String r1 = "Fixed"
            boolean r0 = r0.equals(r1)     // Catch: java.lang.Throwable -> L2b
            if (r0 == 0) goto L37
            r0 = 0
            goto L38
        L2b:
            r0 = move-exception
            goto L49
        L2d:
            java.lang.String r1 = "Compute"
            boolean r0 = r0.equals(r1)     // Catch: java.lang.Throwable -> L2b
            if (r0 == 0) goto L37
            r0 = r3
            goto L38
        L37:
            r0 = -1
        L38:
            if (r0 == 0) goto L41
            if (r0 == r3) goto L3d
            goto L45
        L3d:
            com.amazon.device.ads.PrivacyLocationMode r0 = com.amazon.device.ads.PrivacyLocationMode.COMPUTE     // Catch: java.lang.Throwable -> L2b
            monitor-exit(r4)
            return r0
        L41:
            com.amazon.device.ads.PrivacyLocationMode r0 = com.amazon.device.ads.PrivacyLocationMode.FIXED     // Catch: java.lang.Throwable -> L2b
            monitor-exit(r4)
            return r0
        L45:
            com.amazon.device.ads.PrivacyLocationMode r0 = com.amazon.device.ads.PrivacyLocationMode.RESTRICTED     // Catch: java.lang.Throwable -> L2b
            monitor-exit(r4)
            return r0
        L49:
            monitor-exit(r4)     // Catch: java.lang.Throwable -> L2b
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.amazon.device.ads.DtbSharedPreferences.getPrivacyLocationConfigMode():com.amazon.device.ads.PrivacyLocationMode");
    }

    public String getSisEndpoint() {
        String str = (String) getPref(SIS_ENDPOINT_PREF_NAME, String.class);
        return DtbCommonUtils.isNullOrEmpty(str) ? android.support.v4.media.session.a.t(new StringBuilder(), DtbConstants.SIS_END_POINT, "/api3") : str;
    }

    public Long getSisLastCheckIn() {
        return (Long) getPref(SIS_LAST_CHECKIN_PREF_NAME, Long.class);
    }

    public long getSisLastPing() {
        return ((Long) getPref(SIS_LAST_PING_PREF_NAME, Long.class)).longValue();
    }

    public String getVendorList() {
        return (String) getPref(NON_IAB_VENDORLIST, String.class);
    }

    public String getVersionInUse() {
        return (String) getPref(DTB_VERSION_IN_USE, String.class);
    }

    public Long getWebResoucesLastPing() {
        return (Long) getPref(SIS_LAST_PING_WEB_RESOURCES, Long.class);
    }

    public Long getWrapperDetectionLastPing() {
        return (Long) getPref(SDK_WRAPPER_PING, Long.class);
    }

    public boolean isValidIdfaAvailable() {
        String idfa = getIdfa();
        return (idfa == null || DtbCommonUtils.isNullOrEmpty(idfa.trim()) || idfa.startsWith("0000")) ? false : true;
    }

    public void removeAAXHostName() {
        flushPreference(AAX_HOSTNAME_PREF_NAME);
    }

    public void removeAdid() {
        flushPreference(ADID_PREF_NAME);
    }

    public void removeBidTimeout() {
        flushPreference(BID_TIMEOUT_PREF_NAME);
    }

    public void removeCMPFlavor() {
        flushPreference(NON_IAB_CMP_FLAVOR);
    }

    public void removeConsentStatus() {
        flushPreference(NON_IAB_CONSENT_STATUS);
    }

    public void removeNonIABCustomConsent() {
        flushPreference(NON_IAB_CUSTOM_CONSENT);
    }

    public void removePJTemplate() {
        flushPreference(PJ_TEMPLATE_PREF_NAME);
    }

    public synchronized void removePrivacyLocationConfig() {
        flushPreference(PRIVACY_LOCATION_MODE_PREF_NAME);
        flushPreference(PRIVACY_LOCATION_ACCURACY_IN_METERS_PREF_NAME);
    }

    public void removeVendorList() {
        flushPreference(NON_IAB_VENDORLIST);
    }

    public void resetWebResoucesLastPing() {
        flushPreference(SIS_LAST_PING_WEB_RESOURCES);
    }

    public void resetWrapperDetectionLastPing() {
        flushPreference(SDK_WRAPPER_PING);
    }

    public void saveAaxHostname(String str) {
        saveHostName(str, AAX_HOSTNAME_PREF_NAME);
    }

    public void saveAaxVideoHostname(String str) {
        saveHostName(str, AAX_VIDEO_HOSTNAME_PREF_NAME);
    }

    public void saveAdId(String str) {
        if (str != null) {
            savePref(ADID_PREF_NAME, str);
        }
    }

    public void saveBidTimeout(Integer num) {
        savePref(BID_TIMEOUT_PREF_NAME, num);
    }

    public void saveCMPFlavor(String str) {
        savePref(NON_IAB_CMP_FLAVOR, str);
    }

    public void saveConfigLastCheckIn(long j) {
        savePref(CONFIG_LAST_CHECKIN_PREF_NAME, Long.valueOf(j));
    }

    public synchronized void saveConfigTtlInMilliSeconds(long j) {
        long j2 = j * 1000;
        try {
            if (j2 < 900000) {
                savePref(CONFIG_TTL_PREF_NAME, 172800000L);
            } else {
                savePref(CONFIG_TTL_PREF_NAME, Long.valueOf(j2));
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public void saveConsentStatus(String str) {
        savePref(NON_IAB_CONSENT_STATUS, str);
    }

    public void saveIdfa(String str) {
        if (str != null) {
            savePref(IDFA_PREF_NAME, str);
        } else {
            savePref(IDFA_PREF_NAME, "");
        }
    }

    public void saveIsAdIdChanged(boolean z) {
        savePref(IS_ADID_CHANGED_PREF_NAME, Boolean.valueOf(z));
    }

    public void saveIsAdIdNew(boolean z) {
        savePref(IS_ADID_NEW_PREF_NAME, Boolean.valueOf(z));
    }

    public void saveNonIABCustomConsent(String str) {
        savePref(NON_IAB_CUSTOM_CONSENT, str);
    }

    public synchronized void saveOptOut(Boolean bool) {
        flushPreference(OO_PREF_NAME);
        if (bool != null) {
            savePref(OO_PREF_NAME, bool);
        }
    }

    public void savePJTemplate(JSONObject jSONObject) {
        if (jSONObject != null) {
            savePref(PJ_TEMPLATE_PREF_NAME, jSONObject.toString());
        }
    }

    public synchronized void savePrivacyLocationConfig(JSONObject jSONObject) {
        try {
            savePref(PRIVACY_LOCATION_MODE_PREF_NAME, jSONObject.getString("mode"));
            savePref(PRIVACY_LOCATION_ACCURACY_IN_METERS_PREF_NAME, Float.valueOf((float) jSONObject.getDouble("accuracyInMeters")));
        } catch (JSONException unused) {
            DtbLog.error(LOG_TAG, "Failed to save privacy configurations in shared preferences");
        }
    }

    public boolean saveSisEndpoint(String str) {
        if (DtbCommonUtils.isNullOrEmpty(str)) {
            savePref(SIS_ENDPOINT_PREF_NAME, android.support.v4.media.session.a.t(new StringBuilder(), DtbConstants.SIS_END_POINT, "/api3"));
            return false;
        }
        String str2 = (String) getPref(SIS_ENDPOINT_PREF_NAME, String.class);
        String strK = android.support.v4.media.session.a.k(str, "/api3");
        if (str2 != null && str2.equals(strK)) {
            return false;
        }
        savePref(SIS_ENDPOINT_PREF_NAME, strK);
        return true;
    }

    public void saveSisLastCheckIn(long j) {
        savePref(SIS_LAST_CHECKIN_PREF_NAME, Long.valueOf(j));
    }

    public void saveSisLastPing(long j) {
        savePref(SIS_LAST_PING_PREF_NAME, Long.valueOf(j));
    }

    public void saveVendorList(String str) {
        savePref(NON_IAB_VENDORLIST, str);
    }

    public void saveWebResoucesLastPing(long j) {
        savePref(SIS_LAST_PING_WEB_RESOURCES, Long.valueOf(j));
    }

    public void saveWrapperDetectionLastPing(long j) {
        savePref(SDK_WRAPPER_PING, Long.valueOf(j));
    }

    public void setIsSisRegisterationSuccessful(boolean z) {
        IS_SIS_REGISTERATION_SUCCESSFUL = z;
    }

    public void setVersionInUse(String str) {
        savePref(DTB_VERSION_IN_USE, str);
    }
}
