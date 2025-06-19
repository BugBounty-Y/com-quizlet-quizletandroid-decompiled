package com.onetrust.otpublishers.headless.Internal.Helper;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import androidx.annotation.NonNull;
import com.appsflyer.AdRevenueScheme;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3605e0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.T;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.Keys.OTIABTCFKeys;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

/* loaded from: classes2.dex */
public final class f {
    public final com.onetrust.otpublishers.headless.Internal.Preferences.e a;
    public final Context b;

    public f(@NonNull Context context) {
        this.b = context;
        this.a = new com.onetrust.otpublishers.headless.Internal.Preferences.e(context);
    }

    public final void a(String str) {
        if (str != null) {
            try {
                JSONObject jSONObject = new JSONObject(str);
                v vVar = new v(this.b);
                vVar.b(1, jSONObject.optString(AdRevenueScheme.COUNTRY), jSONObject.optString("state"));
                vVar.b(3, jSONObject.optString(AdRevenueScheme.COUNTRY), jSONObject.optString("state"));
                OTLogger.c("OTSDKMigration", 2, "Saving Consent given location from Web SDK, country : " + jSONObject.optString(AdRevenueScheme.COUNTRY) + "state : " + jSONObject.optString("state"));
            } catch (Exception e) {
                Z.n("Error while migrating consent given location, err : ", e, "OTSDKMigration", 3);
            }
        }
    }

    public final void b(JSONObject jSONObject) {
        String str;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        boolean z;
        com.onetrust.otpublishers.headless.Internal.Preferences.e eVar = this.a;
        eVar.f(1);
        JSONObject jSONObject2 = new JSONObject();
        Context context = this.b;
        SharedPreferences defaultSharedPreferences = PreferenceManager.getDefaultSharedPreferences(context);
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublisherssdk.Internal.preference", 0);
        String string = defaultSharedPreferences.getString("optanonCookieConsentGroups", "");
        String string2 = defaultSharedPreferences.getString("completeOptanonCookie", "");
        String string3 = defaultSharedPreferences.getString("OTuserConsentGivenLocation", "");
        int i = sharedPreferences.getInt("OT_BANNER_SHOWN_TO_USER", -1);
        String string4 = defaultSharedPreferences.getString(OTIABTCFKeys.IABTCF_SPECIALFEATURESOPTINS, "");
        String string5 = defaultSharedPreferences.getString("IABTCF_PurposeConsents", "");
        String string6 = defaultSharedPreferences.getString(OTIABTCFKeys.IABTCF_PURPOSELEGITIMATEINTERESTS, "");
        String string7 = defaultSharedPreferences.getString("IABTCF_VendorConsents", "");
        String string8 = defaultSharedPreferences.getString("IABTCF_VendorLegitimateInterests", "");
        try {
            JSONObject jSONObject3 = !com.onetrust.otpublishers.headless.Internal.a.j(string) ? new JSONObject(string) : new JSONObject();
            JSONArray jSONArray = new JSONArray(new JSONTokener(string2).nextValue().toString());
            int i2 = 0;
            while (true) {
                if (i2 >= jSONArray.length()) {
                    str = string7;
                    break;
                }
                str = string7;
                if (jSONArray.getJSONObject(i2).optString("name", "").equals("OptanonAlertBoxClosed")) {
                    jSONObject2 = jSONArray.getJSONObject(i2);
                    break;
                } else {
                    i2++;
                    string7 = str;
                }
            }
            d(jSONObject2);
            a(string3);
            SharedPreferences sharedPreferences2 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
            if (AbstractC3605e0.a(context.getSharedPreferences("com.onetrust.otpublishers.headless.preference".concat("OTT_DEFAULT_USER"), 0).getString("OT_ENABLE_MULTI_PROFILE", Boolean.FALSE.toString()))) {
                fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences2, sharedPreferences2.getString("OT_ACTIVE_PROFILE_ID", ""));
                z = true;
            } else {
                fVar = null;
                z = false;
            }
            if (z) {
                sharedPreferences2 = fVar;
            }
            if (sharedPreferences2.getInt("OneTrustBannerShownToUser", -1) < 1 && i == 1) {
                com.onetrust.otpublishers.headless.Internal.a.b(context, 1);
            }
            JSONArray jSONArrayNames = jSONObject3.names();
            if (jSONArrayNames != null) {
                for (int i3 = 0; i3 < jSONArrayNames.length(); i3++) {
                    jSONObject.put(jSONArrayNames.getString(i3), Integer.parseInt(jSONObject3.getString(jSONArrayNames.getString(i3))));
                }
            }
            c(jSONObject, string4, string5, string6, str, string8, jSONObject2);
            if (eVar.a.b().getInt("OT_MIGRATION_STATUS", 5) != 6) {
                eVar.f(3);
            }
        } catch (JSONException e) {
            eVar.f(2);
            T.d(e, new StringBuilder("error while syncing data from Web SDK, err: "), "OneTrust", 6);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:119:0x0253 A[ADDED_TO_REGION, REMOVE, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:82:0x0225 A[ADDED_TO_REGION] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void c(org.json.JSONObject r18, java.lang.String r19, java.lang.String r20, java.lang.String r21, java.lang.String r22, java.lang.String r23, org.json.JSONObject r24) throws org.json.JSONException, java.lang.NumberFormatException {
        /*
            Method dump skipped, instructions count: 648
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.f.c(org.json.JSONObject, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, org.json.JSONObject):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x004a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void d(org.json.JSONObject r7) throws org.json.JSONException, java.text.ParseException {
        /*
            r6 = this;
            java.lang.String r0 = "value"
            boolean r1 = r7.has(r0)
            if (r1 == 0) goto L79
            java.lang.String r7 = r7.getString(r0)
            boolean r0 = com.onetrust.otpublishers.headless.Internal.a.j(r7)
            if (r0 != 0) goto L79
            java.text.SimpleDateFormat r0 = new java.text.SimpleDateFormat
            java.lang.String r1 = "yyyy-MM-dd'T'HH:mm:ss"
            r0.<init>(r1)
            java.lang.String r1 = "UTC"
            java.util.TimeZone r1 = java.util.TimeZone.getTimeZone(r1)
            r0.setTimeZone(r1)
            java.lang.String r1 = "OTSDKMigration"
            r2 = -1
            if (r7 == 0) goto L4a
            java.util.Date r7 = r0.parse(r7)     // Catch: java.text.ParseException -> L33
            if (r7 == 0) goto L4a
            long r4 = r7.getTime()     // Catch: java.text.ParseException -> L33
            goto L4b
        L33:
            r7 = move-exception
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            java.lang.String r4 = "Error while migrating consent given time, err : "
            r0.<init>(r4)
            java.lang.String r7 = r7.getMessage()
            r0.append(r7)
            java.lang.String r7 = r0.toString()
            r0 = 6
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r1, r0, r7)
        L4a:
            r4 = r2
        L4b:
            int r7 = (r4 > r2 ? 1 : (r4 == r2 ? 0 : -1))
            if (r7 == 0) goto L73
            java.lang.String r7 = java.lang.String.valueOf(r4)
            com.onetrust.otpublishers.headless.Internal.Preferences.e r0 = r6.a
            r0.getClass()
            r2 = 4
            java.lang.String r3 = "Updating consent given time, timeStamp = "
            java.lang.String r4 = "OTSPUtils"
            com.google.android.gms.internal.mlkit_vision_document_scanner.K.c(r3, r2, r7, r4)
            com.onetrust.otpublishers.headless.Internal.Preferences.d r0 = r0.a
            android.content.SharedPreferences r0 = r0.b()
            android.content.SharedPreferences$Editor r0 = r0.edit()
            java.lang.String r2 = "OTT_LAST_GIVEN_CONSENT"
            android.content.SharedPreferences$Editor r7 = r0.putString(r2, r7)
            r7.apply()
        L73:
            java.lang.String r7 = "Saving Consent given time from WebSDK"
            r0 = 2
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r1, r0, r7)
        L79:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.f.d(org.json.JSONObject):void");
    }
}
