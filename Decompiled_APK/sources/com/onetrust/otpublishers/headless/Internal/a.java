package com.onetrust.otpublishers.headless.Internal;

import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import androidx.browser.customtabs.k;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.fragment.app.Fragment;
import androidx.work.impl.model.c;
import com.google.android.gms.internal.mlkit_vision_document_scanner.K;
import com.google.android.gms.internal.mlkit_vision_document_scanner.P;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Q;
import com.google.android.gms.internal.mlkit_vision_document_scanner.V;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Helper.h;
import com.onetrust.otpublishers.headless.Internal.Helper.j;
import com.onetrust.otpublishers.headless.Internal.Helper.p;
import com.onetrust.otpublishers.headless.Internal.Helper.r;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Internal.Preferences.d;
import com.onetrust.otpublishers.headless.Internal.Preferences.e;
import com.onetrust.otpublishers.headless.Internal.Preferences.f;
import com.onetrust.otpublishers.headless.Public.DataModel.OTProfileSyncParams;
import com.onetrust.otpublishers.headless.Public.DataModel.OTSdkParams;
import com.onetrust.otpublishers.headless.Public.Keys.OTGppKeys;
import com.onetrust.otpublishers.headless.Public.Keys.OTIABCCPAKeys;
import com.onetrust.otpublishers.headless.Public.Keys.OTIABTCFKeys;
import com.onetrust.otpublishers.headless.Public.OTThemeConstants;
import com.onetrust.otpublishers.headless.UI.TVUI.fragments.g;
import com.onetrust.otpublishers.headless.UI.fragment.C4063g;
import com.onetrust.otpublishers.headless.UI.fragment.D;
import com.onetrust.otpublishers.headless.UI.fragment.I;
import com.onetrust.otpublishers.headless.UI.fragment.l;
import com.onetrust.otpublishers.headless.UI.fragment.m;
import com.onetrust.otpublishers.headless.UI.fragment.s;
import com.onetrust.otpublishers.headless.UI.fragment.t;
import com.onetrust.otpublishers.headless.gpp.b;
import java.util.HashMap;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class a {
    public static OTSdkParams a(Context context) {
        f fVar;
        boolean z = false;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        String string = sharedPreferences.getString("OTT_REGION_CODE", null);
        String string2 = sharedPreferences.getString("OTT_COUNTRY_CODE", null);
        String string3 = sharedPreferences.getString("OTT_CREATE_CONSENT_PROFILE_STRING", null);
        String string4 = sharedPreferences.getString("OTT_PROFILE_SYNC_PROFILE_STRING", null);
        String string5 = sharedPreferences.getString("OTT_DATA_SUBJECT_IDENTIFIER", null);
        String string6 = sharedPreferences.getString("OTT_IDENTIFIER_TYPE", null);
        String string7 = sharedPreferences.getString("OTT_PROFILE_SYNC_PROFILE_AUTH", null);
        String string8 = sharedPreferences.getString("OTT_PROFILE_TENANT_ID", null);
        String string9 = sharedPreferences.getString("OTT_PROFILE_SYNC_GROUP_ID", null);
        OTProfileSyncParams.OTProfileSyncParamsBuilder oTProfileSyncParamsBuilderNewInstance = OTProfileSyncParams.OTProfileSyncParamsBuilder.newInstance();
        if (string4 != null) {
            oTProfileSyncParamsBuilderNewInstance = oTProfileSyncParamsBuilderNewInstance.setSyncProfile(string4);
        }
        if (string5 != null) {
            oTProfileSyncParamsBuilderNewInstance = oTProfileSyncParamsBuilderNewInstance.setIdentifier(string5);
        }
        if (string6 != null) {
            oTProfileSyncParamsBuilderNewInstance = oTProfileSyncParamsBuilderNewInstance.setIdentifierType(string6);
        }
        if (string7 != null) {
            oTProfileSyncParamsBuilderNewInstance = oTProfileSyncParamsBuilderNewInstance.setSyncProfileAuth(string7);
        }
        if (string8 != null) {
            oTProfileSyncParamsBuilderNewInstance = oTProfileSyncParamsBuilderNewInstance.setTenantId(string8);
        }
        if (string9 != null) {
            oTProfileSyncParamsBuilderNewInstance = oTProfileSyncParamsBuilderNewInstance.setSyncGroupId(string9);
        }
        OTSdkParams.SdkParamsBuilder profileSyncParams = OTSdkParams.SdkParamsBuilder.newInstance().setProfileSyncParams(oTProfileSyncParamsBuilderNewInstance.build());
        if (string3 != null) {
            profileSyncParams = profileSyncParams.shouldCreateProfile(string3);
        }
        String string10 = sharedPreferences.getString("OTT_SDK_API_VERSION", null);
        if (string10 != null) {
            profileSyncParams = profileSyncParams.setAPIVersion(string10);
        }
        if (string != null) {
            profileSyncParams = profileSyncParams.setOTRegionCode(string);
        }
        if (string2 != null) {
            profileSyncParams = profileSyncParams.setOTCountryCode(string2);
        }
        return profileSyncParams.build();
    }

    public static void b(Context context, int i) {
        f fVar;
        boolean z = false;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Z.r(Boolean.FALSE, Y.a(context), "OT_ENABLE_MULTI_PROFILE")) {
            fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        sharedPreferences.edit().putInt("OneTrustBannerShownToUser", i).apply();
    }

    public static void c(Context context, String str) {
        String strD;
        try {
            Uri uri = Uri.parse(str);
            c cVarC = new k(0, false).c();
            if (com.google.mlkit.common.internal.model.a.n(context, "OT_BANNERloadExternalURL")) {
                cVarC.v(context, uri);
            }
        } catch (ActivityNotFoundException unused) {
            strD = AbstractC0147y.d("Could not load the url : URL passed may be invalid ", str);
            OTLogger.c("OneTrust", 6, strD);
        } catch (Exception unused2) {
            strD = "Could not find class androidx.browser.customtabs.CustomTabsIntent$Builder, add implementation 'androidx.browser:browser:{version}' to gradle file";
            OTLogger.c("OneTrust", 6, strD);
        }
    }

    public static void d(d dVar, String str) {
        dVar.b().edit().putString("OT_MOBILE_DATA_OVERRIDE_THEME", str).apply();
    }

    public static void e(JSONArray jSONArray, Context context, boolean z) {
        boolean zL = new e(context).l();
        if (z) {
            OTLogger.c("OTUtils", 3, "Clearing IAB data from storage as saved TC string got expired");
            new j(context).i(jSONArray, new JSONObject(), false);
            h.a(zL).getClass();
            h.k(context);
            b bVar = new b(context);
            HashMap map = bVar.b;
            if (map.isEmpty()) {
                bVar.c();
            }
            if (map.keySet().isEmpty()) {
                return;
            }
            for (String str : map.keySet()) {
                if (!j(str) && (str.startsWith("IABGPP_TCFEU2_") || str.equalsIgnoreCase(OTGppKeys.IAB_GPP_TCFEU2_STRING))) {
                    bVar.c.b(str);
                }
            }
        }
    }

    public static boolean f(Fragment fragment, String str) {
        if (str.equals("LAYER_1")) {
            return (fragment instanceof C4063g) || (fragment instanceof l) || (fragment instanceof g);
        }
        if (str.equals("LAYER_2")) {
            return (fragment instanceof com.onetrust.otpublishers.headless.UI.fragment.k) || (fragment instanceof D);
        }
        if (str.equals("LAYER_3")) {
            return (fragment instanceof I) || (fragment instanceof s) || (fragment instanceof m) || (fragment instanceof t);
        }
        return false;
    }

    public static boolean g(androidx.fragment.app.I i, String str) {
        Fragment fragmentE = i.getSupportFragmentManager().E(str);
        return f(fragmentE, "LAYER_1") || f(fragmentE, "LAYER_2") || f(fragmentE, "LAYER_3");
    }

    public static boolean h(String str, boolean z) {
        return j(str) ? z : Boolean.parseBoolean(str);
    }

    public static boolean i(JSONArray jSONArray, JSONObject jSONObject, long j, Context context) {
        if (-1 != j && !P.j(context)) {
            int days = (int) TimeUnit.MILLISECONDS.toDays(System.currentTimeMillis() - j);
            if (jSONObject != null && jSONObject.has("IABReconsentFrequencyDays")) {
                try {
                    boolean z = days > jSONObject.getInt("IABReconsentFrequencyDays");
                    e(jSONArray, context, z);
                    return z;
                } catch (JSONException e) {
                    Z.p("Error on getting IAB reconsent frequency days,  message = ", e, "OTUtils", 6);
                }
            }
        }
        return false;
    }

    public static boolean j(String str) {
        return str == null || str.length() == 0;
    }

    public static boolean k(Context context, String str) {
        int i;
        if (str == null) {
            OTLogger.c("OTUtils", 4, "setDataSubjectIdentifier: Pass a valid identifier.");
            return false;
        }
        r rVar = new r(context);
        if (str.isEmpty()) {
            SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preference".concat("OTT_DEFAULT_USER"), 0);
            String string = sharedPreferences.getString("OT_GENERIC_PROFILE_IDENTIFIER", null);
            if (j(string)) {
                string = UUID.randomUUID().toString();
                V.a(sharedPreferences, "OT_GENERIC_PROFILE_IDENTIFIER", string);
            }
            str = string;
            K.c("Generated identifier = ", 4, str, "OTUtils");
            i = 1;
        } else {
            i = 2;
        }
        e eVar = rVar.b;
        eVar.c(i);
        eVar.k(str);
        rVar.c();
        return true;
    }

    public static boolean l(String str) {
        if (j(str)) {
            return false;
        }
        return "IAB2V2".equalsIgnoreCase(str);
    }

    public static boolean m(Context context) throws PackageManager.NameNotFoundException {
        boolean z;
        try {
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), 4096);
            if (packageInfo != null) {
                String[] strArr = packageInfo.requestedPermissions;
                if (strArr == null) {
                    OTLogger.c("OTUtils", 3, "App requestedPermissionsList is empty.");
                } else {
                    for (String str : strArr) {
                        if ("com.google.android.gms.permission.AD_ID".equalsIgnoreCase(str)) {
                            z = true;
                            break;
                        }
                    }
                }
                z = false;
                OTLogger.c("GoogleAdInfo", 3, "Is appRequestedGoogleAdPermission = " + z);
                return z;
            }
        } catch (PackageManager.NameNotFoundException e) {
            OTLogger.c("GoogleAdInfo", 6, "Issue on reading PackageInfo for google ad permission. Error = " + e.getMessage());
        }
        return false;
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x008b A[RETURN] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean n(java.lang.String r11) {
        /*
            boolean r0 = j(r11)
            r1 = 0
            if (r0 == 0) goto L9
            goto La5
        L9:
            java.util.HashSet r0 = new java.util.HashSet
            java.lang.String[] r2 = java.util.Locale.getISOLanguages()
            java.util.List r2 = java.util.Arrays.asList(r2)
            r0.<init>(r2)
            java.util.HashSet r2 = new java.util.HashSet
            java.lang.String[] r3 = java.util.Locale.getISOCountries()
            java.util.List r3 = java.util.Arrays.asList(r3)
            r2.<init>(r3)
            java.util.HashSet r3 = new java.util.HashSet
            java.util.Locale[] r4 = java.util.Locale.getAvailableLocales()
            int r5 = r4.length
            r6 = 1
            int r5 = r5 + r6
            java.lang.String[] r5 = new java.lang.String[r5]
            r7 = r1
        L2f:
            int r8 = r4.length
            java.lang.String r9 = "-"
            if (r7 >= r8) goto L49
            r8 = r4[r7]
            java.lang.String r8 = r8.toString()
            java.lang.String r10 = "_"
            java.lang.String r8 = r8.replace(r10, r9)
            java.lang.String r8 = r8.trim()
            r5[r7] = r8
            int r7 = r7 + 1
            goto L2f
        L49:
            java.util.List r4 = java.util.Arrays.asList(r5)
            r3.<init>(r4)
            boolean r4 = r11.contains(r9)
            if (r4 != 0) goto L69
            java.util.Locale r2 = java.util.Locale.ENGLISH
            java.lang.String r11 = r11.toLowerCase(r2)
            boolean r2 = r3.contains(r11)
            if (r2 != 0) goto L8b
            boolean r11 = r0.contains(r11)
            if (r11 == 0) goto La5
            goto L8b
        L69:
            java.lang.String[] r3 = r11.split(r9)     // Catch: java.lang.ArrayIndexOutOfBoundsException -> L8c
            r3 = r3[r6]     // Catch: java.lang.ArrayIndexOutOfBoundsException -> L8c
            java.util.Locale r4 = java.util.Locale.ENGLISH     // Catch: java.lang.ArrayIndexOutOfBoundsException -> L8c
            java.lang.String r3 = r3.toUpperCase(r4)     // Catch: java.lang.ArrayIndexOutOfBoundsException -> L8c
            java.lang.String[] r11 = r11.split(r9)     // Catch: java.lang.ArrayIndexOutOfBoundsException -> L8c
            r11 = r11[r1]     // Catch: java.lang.ArrayIndexOutOfBoundsException -> L8c
            java.lang.String r11 = r11.toLowerCase(r4)     // Catch: java.lang.ArrayIndexOutOfBoundsException -> L8c
            boolean r11 = r0.contains(r11)     // Catch: java.lang.ArrayIndexOutOfBoundsException -> L8c
            if (r11 == 0) goto La5
            boolean r11 = r2.contains(r3)     // Catch: java.lang.ArrayIndexOutOfBoundsException -> L8c
            if (r11 == 0) goto La5
        L8b:
            return r6
        L8c:
            r11 = move-exception
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            java.lang.String r2 = "Exception while validating language code, err: "
            r0.<init>(r2)
            java.lang.String r11 = r11.getMessage()
            r0.append(r11)
            java.lang.String r11 = r0.toString()
            java.lang.String r0 = "OTUtils"
            r2 = 3
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r0, r2, r11)
        La5:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.a.n(java.lang.String):boolean");
    }

    public static boolean o(Context context) {
        boolean z;
        f fVar;
        String string = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOT_SDK_APP_CONFIGURATION", 0).getString("OT_UX_SDK_THEME", OTThemeConstants.NO_SDK_THEME_OVERRIDE);
        if (j(string)) {
            string = OTThemeConstants.NO_SDK_THEME_OVERRIDE;
        }
        boolean zEqualsIgnoreCase = OTThemeConstants.OT_THEME_APP_COMPACT_LIGHT_NO_ACTION_BAR.equalsIgnoreCase(string);
        if (!zEqualsIgnoreCase) {
            String string2 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOT_SDK_APP_CONFIGURATION", 0).getString("OT_UX_SDK_THEME", OTThemeConstants.NO_SDK_THEME_OVERRIDE);
            if (j(string2)) {
                string2 = OTThemeConstants.NO_SDK_THEME_OVERRIDE;
            }
            zEqualsIgnoreCase = OTThemeConstants.OT_THEME_APP_COMPACT_LIGHT_NO_ACTION_BAR_LANDSCAPE_FULL_SCREEN.equalsIgnoreCase(string2);
        }
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Z.r(Boolean.FALSE, context.getSharedPreferences("com.onetrust.otpublishers.headless.preference".concat("OTT_DEFAULT_USER"), 0), "OT_ENABLE_MULTI_PROFILE")) {
            fVar = new f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            z = false;
            fVar = null;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        String string3 = sharedPreferences.getString("OT_MOBILE_DATA_OVERRIDE_THEME", null);
        if (!j(string3)) {
            OTLogger.c("OTUtils", 3, "Mobile data, overrideTheme = " + string3);
            if (OTThemeConstants.NO_SDK_THEME_OVERRIDE.equalsIgnoreCase(string3)) {
                return false;
            }
            if (OTThemeConstants.OT_THEME_APP_COMPACT_LIGHT_NO_ACTION_BAR.equalsIgnoreCase(string3)) {
                return true;
            }
        }
        return zEqualsIgnoreCase;
    }

    public static void p(Context context) {
        try {
            com.onetrust.otpublishers.headless.Internal.profile.c cVar = new com.onetrust.otpublishers.headless.Internal.profile.c(context);
            String string = cVar.a.b().getString("OT_MULTI_PROFILE_ID_MAP", null);
            if (!j(string)) {
                JSONArray jSONArray = new JSONArray(string);
                for (int i = 0; i < jSONArray.length(); i++) {
                    cVar.i(jSONArray.getString(i));
                }
            }
        } catch (JSONException e) {
            Z.p("Error on clearing multi-profile files. Error = ", e, "OneTrust", 6);
        }
        new d(context, "OTT_DEFAULT_USER").a();
        SharedPreferences sharedPreferences = new p(context).c;
        if (sharedPreferences.contains(OTIABCCPAKeys.OT_IAB_US_PRIVACY_STRING)) {
            sharedPreferences.edit().remove(OTIABCCPAKeys.OT_IAB_US_PRIVACY_STRING).apply();
            OTLogger.c("IABCCPA_Consent", 4, "CCPA String deleted");
        }
        b bVar = new b(context);
        HashMap map = bVar.b;
        if (map.isEmpty()) {
            bVar.c();
        }
        if (!map.keySet().isEmpty()) {
            for (String str : map.keySet()) {
                if (!j(str)) {
                    bVar.c.b(str);
                }
            }
        }
        new com.onetrust.otpublishers.headless.Internal.Preferences.a(context).b(OTIABTCFKeys.IABTCF_ADD_TL_CONSENT);
        boolean zL = new e(context).l();
        h.a(zL).getClass();
        if (!j(h.q(context).toString())) {
            h.a(zL).getClass();
            h.k(context);
        }
        b(context, -1);
    }
}
