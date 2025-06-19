package com.onetrust.otpublishers.headless.Internal.Helper;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.appsflyer.AdRevenueScheme;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Q;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.DataModel.OTGeolocationModel;
import com.onetrust.otpublishers.headless.Public.Keys.OTGppKeys;
import com.onetrust.otpublishers.headless.Public.Keys.OTIABCCPAKeys;
import com.onetrust.otpublishers.headless.Public.OTCCPAGeolocationConstants;
import java.util.Locale;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class p {
    public final Context a;
    public final com.onetrust.otpublishers.headless.Internal.Preferences.d b;
    public final SharedPreferences c;

    public p(@NonNull Context context) {
        this.a = context;
        this.c = PreferenceManager.getDefaultSharedPreferences(context);
        this.b = new com.onetrust.otpublishers.headless.Internal.Preferences.d(context);
    }

    public final void a(JSONObject jSONObject) {
        OTGeolocationModel oTGeolocationModel;
        String strE;
        boolean zHas;
        boolean z;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        String strOptString = jSONObject.optString("parentCCPACategory", "");
        String strOptString2 = jSONObject.optString("ccpaGeo", "");
        boolean zOptBoolean = jSONObject.optBoolean("ccpaLspa", false);
        boolean zOptBoolean2 = jSONObject.optBoolean("ccpaExpNotice", false);
        boolean zOptBoolean3 = jSONObject.optBoolean("computeCCPA", false);
        com.onetrust.otpublishers.headless.Internal.Preferences.d dVar = this.b;
        dVar.b().edit().putBoolean("OT_COMPUTE_CCPA_REGION", zOptBoolean3).apply();
        Context context = this.a;
        if (!zOptBoolean3) {
            d();
            String string = dVar.b().getString("OT_DATA_DOWNLOADED_GEO_LOCATION", "");
            if (!com.onetrust.otpublishers.headless.Internal.a.j(strOptString)) {
                SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                if (Q.a(context)) {
                    SharedPreferences sharedPreferences2 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preference.OTT_USER_" + new com.onetrust.otpublishers.headless.Internal.profile.c(context).n(sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", "")), 0);
                    sharedPreferences.edit();
                    sharedPreferences2.edit();
                }
                if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                    oTGeolocationModel = null;
                } else {
                    oTGeolocationModel = new OTGeolocationModel();
                    try {
                        JSONObject jSONObject2 = new JSONObject(string);
                        oTGeolocationModel.country = jSONObject2.optString(AdRevenueScheme.COUNTRY);
                        oTGeolocationModel.state = jSONObject2.optString("state");
                    } catch (JSONException e) {
                        Z.p("error in formatting ott data with err = ", e, "GLDataHandler", 6);
                    }
                }
                strE = (!OTCCPAGeolocationConstants.ALL.equalsIgnoreCase(strOptString2) && (com.onetrust.otpublishers.headless.Internal.a.j(strOptString2) || oTGeolocationModel == null || !oTGeolocationModel.compareLocation(strOptString2))) ? AbstractC0147y.e("CCPA string not updated for location ", strOptString2, " as user's location ", string, " is out of ccpa configured region") : "Compute CCPA disabled for this template from OneTrust UI";
            }
            OTLogger.c("OneTrust", 5, strE);
        } else if (!com.onetrust.otpublishers.headless.Internal.a.j(strOptString)) {
            String string2 = dVar.b().getString("OT_UI_VALID_GROUP_IDS", "");
            if (com.onetrust.otpublishers.headless.Internal.a.j(string2)) {
                zHas = false;
            } else {
                Locale locale = Locale.ENGLISH;
                zHas = new JSONObject(string2.toLowerCase(locale)).has(strOptString.toLowerCase(locale));
            }
            if (zHas) {
                SharedPreferences sharedPreferences3 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                if (Z.r(Boolean.FALSE, context.getSharedPreferences("com.onetrust.otpublishers.headless.preference".concat("OTT_DEFAULT_USER"), 0), "OT_ENABLE_MULTI_PROFILE")) {
                    fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences3, sharedPreferences3.getString("OT_ACTIVE_PROFILE_ID", ""));
                    z = true;
                } else {
                    z = false;
                    fVar = null;
                }
                new com.onetrust.otpublishers.headless.gpp.b(context);
                if (z) {
                    sharedPreferences3 = fVar;
                }
                String str = sharedPreferences3.getBoolean("OT_GPP_IS_ENABLED", false) ? OTGppKeys.IAB_GPP_USP1_STRING : OTIABCCPAKeys.OT_IAB_US_PRIVACY_STRING;
                SharedPreferences sharedPreferences4 = this.c;
                if (!sharedPreferences4.contains(str)) {
                    sharedPreferences4.edit().putString(str, "1---").apply();
                    OTLogger.c("IABCCPA_Consent", 4, "CCPA initialized? = " + sharedPreferences4.contains(str));
                }
                SharedPreferences.Editor editorEdit = dVar.b().edit();
                editorEdit.putString("OT_CCPA_CATEGORY_ID", strOptString);
                editorEdit.putString("OTT_CCPA_GEOLOCATIONS", strOptString2);
                editorEdit.putBoolean("OTT_EXPLICIT_NOTICE", zOptBoolean2);
                editorEdit.putBoolean("OTT_AGREEMENT_TERMS_APPLIES", zOptBoolean);
                editorEdit.apply();
                b(new com.onetrust.otpublishers.headless.Internal.Preferences.e(context).a(strOptString) == 1, false);
            } else {
                OTLogger.c("OneTrust", 5, "Invalid CCPA configuration. Please assign SDKs to the CCPA category or its subgroups.");
            }
        }
        if (com.onetrust.otpublishers.headless.Internal.a.j(c())) {
            return;
        }
        new JSONArray();
        String strC = c();
        try {
            JSONObject jSONObject3 = new JSONObject(dVar.b().getString("OTT_PARENT_GROUPS", ""));
            if (jSONObject3.has(strC)) {
                dVar.b().edit().putString("OTT_CCPA_CUSTOM_GROUP_IDS", jSONObject3.getJSONArray(strC).toString()).apply();
            }
        } catch (JSONException e2) {
            Z.p("Error when CCPA subgroups are fetched, err : ", e2, "IABCCPA_Consent", 6);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:105:0x0280  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x0361 A[Catch: JSONException -> 0x0300, TryCatch #5 {JSONException -> 0x0300, blocks: (B:113:0x02af, B:114:0x02ba, B:116:0x02c0, B:118:0x02f5, B:122:0x0305, B:125:0x0310, B:127:0x0318, B:129:0x031e, B:140:0x034d, B:142:0x0361, B:146:0x0383, B:145:0x0378, B:136:0x0337, B:139:0x034a, B:147:0x038b), top: B:181:0x02af }] */
    /* JADX WARN: Removed duplicated region for block: B:143:0x0375  */
    /* JADX WARN: Removed duplicated region for block: B:145:0x0378 A[Catch: JSONException -> 0x0300, TryCatch #5 {JSONException -> 0x0300, blocks: (B:113:0x02af, B:114:0x02ba, B:116:0x02c0, B:118:0x02f5, B:122:0x0305, B:125:0x0310, B:127:0x0318, B:129:0x031e, B:140:0x034d, B:142:0x0361, B:146:0x0383, B:145:0x0378, B:136:0x0337, B:139:0x034a, B:147:0x038b), top: B:181:0x02af }] */
    /* JADX WARN: Removed duplicated region for block: B:152:0x03ab  */
    /* JADX WARN: Removed duplicated region for block: B:186:0x0383 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:187:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:78:0x01a7 A[PHI: r22 r23
  0x01a7: PHI (r22v3 java.lang.String) = (r22v7 java.lang.String), (r22v8 java.lang.String) binds: [B:77:0x01a5, B:69:0x0192] A[DONT_GENERATE, DONT_INLINE]
  0x01a7: PHI (r23v1 java.lang.String) = (r23v3 java.lang.String), (r23v6 java.lang.String) binds: [B:77:0x01a5, B:69:0x0192] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:80:0x01ab  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x01bc  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x01c7  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x01d0  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x01e0  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x01f7  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean b(boolean r25, boolean r26) {
        /*
            Method dump skipped, instructions count: 1021
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.p.b(boolean, boolean):boolean");
    }

    public final String c() {
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        Context context = this.a;
        boolean z = false;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        return sharedPreferences.getString("OT_CCPA_CATEGORY_ID", "");
    }

    public final void d() {
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        boolean z;
        Context context = this.a;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
            z = false;
        }
        new com.onetrust.otpublishers.headless.gpp.b(context);
        if (z) {
            sharedPreferences = fVar;
        }
        if (!sharedPreferences.getBoolean("OT_GPP_IS_ENABLED", false)) {
            this.c.edit().remove(OTIABCCPAKeys.OT_IAB_US_PRIVACY_STRING).apply();
            return;
        }
        SharedPreferences defaultSharedPreferences = PreferenceManager.getDefaultSharedPreferences(context);
        if (defaultSharedPreferences.contains(OTIABCCPAKeys.OT_IAB_US_PRIVACY_STRING)) {
            defaultSharedPreferences.edit().remove(OTIABCCPAKeys.OT_IAB_US_PRIVACY_STRING).apply();
        }
    }
}
