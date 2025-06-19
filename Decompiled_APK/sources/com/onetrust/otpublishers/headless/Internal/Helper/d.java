package com.onetrust.otpublishers.headless.Internal.Helper;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import androidx.annotation.NonNull;
import com.google.android.gms.internal.mlkit_vision_document_scanner.L;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.uiutils.OTVendorUtils;
import java.util.Iterator;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class d {
    public final SharedPreferences a;
    public final Context b;
    public final com.onetrust.otpublishers.headless.Internal.Preferences.e c;
    public final com.onetrust.otpublishers.headless.Internal.Preferences.d d;

    public d(@NonNull Context context) {
        this.b = context;
        this.c = new com.onetrust.otpublishers.headless.Internal.Preferences.e(context);
        this.d = new com.onetrust.otpublishers.headless.Internal.Preferences.d(context);
        this.a = PreferenceManager.getDefaultSharedPreferences(context);
    }

    public static boolean d(String str, int i, JSONObject jSONObject, int i2, String str2) throws JSONException {
        int iOptInt = jSONObject.optInt(str2, -1);
        if (iOptInt >= 0) {
            int i3 = (str == null || com.onetrust.otpublishers.headless.Internal.a.j(str) || i2 <= 0 || i2 > i) ? 0 : Integer.parseInt(String.valueOf(str.charAt(i2 - 1)));
            if (i3 != iOptInt) {
                jSONObject.put(str2, i3);
                return true;
            }
        }
        return false;
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x005b A[Catch: Exception -> 0x0037, TRY_LEAVE, TryCatch #1 {Exception -> 0x0037, blocks: (B:8:0x0025, B:10:0x0031, B:17:0x0055, B:19:0x005b, B:16:0x0050, B:15:0x003a), top: B:31:0x0025, inners: #0 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a() {
        /*
            r7 = this;
            java.lang.String r0 = "OneTrust"
            android.content.Context r1 = r7.b
            java.lang.String r2 = "com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER"
            r3 = 0
            android.content.SharedPreferences r2 = r1.getSharedPreferences(r2, r3)
            boolean r4 = com.google.android.gms.internal.mlkit_vision_document_scanner.Q.a(r1)
            java.lang.String r5 = ""
            if (r4 == 0) goto L20
            java.lang.String r4 = "OT_ACTIVE_PROFILE_ID"
            java.lang.String r4 = r2.getString(r4, r5)
            com.onetrust.otpublishers.headless.Internal.Preferences.f r6 = new com.onetrust.otpublishers.headless.Internal.Preferences.f
            r6.<init>(r1, r2, r4)
            r4 = 1
            goto L22
        L20:
            r6 = 0
            r4 = r3
        L22:
            if (r4 == 0) goto L25
            r2 = r6
        L25:
            java.lang.String r4 = "OTT_CULTURE_DOMAIN_DATA"
            java.lang.String r2 = r2.getString(r4, r5)     // Catch: java.lang.Exception -> L37
            boolean r4 = com.onetrust.otpublishers.headless.Internal.a.j(r2)     // Catch: java.lang.Exception -> L37
            if (r4 != 0) goto L50
            org.json.JSONObject r4 = new org.json.JSONObject     // Catch: java.lang.Exception -> L37 org.json.JSONException -> L39
            r4.<init>(r2)     // Catch: java.lang.Exception -> L37 org.json.JSONException -> L39
            goto L55
        L37:
            r2 = move-exception
            goto L60
        L39:
            r2 = move-exception
            java.lang.StringBuilder r4 = new java.lang.StringBuilder     // Catch: java.lang.Exception -> L37
            java.lang.String r6 = "error while returning culture domain data, err: "
            r4.<init>(r6)     // Catch: java.lang.Exception -> L37
            java.lang.String r2 = r2.getMessage()     // Catch: java.lang.Exception -> L37
            r4.append(r2)     // Catch: java.lang.Exception -> L37
            java.lang.String r2 = r4.toString()     // Catch: java.lang.Exception -> L37
            r4 = 6
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r0, r4, r2)     // Catch: java.lang.Exception -> L37
        L50:
            org.json.JSONObject r4 = new org.json.JSONObject     // Catch: java.lang.Exception -> L37
            r4.<init>()     // Catch: java.lang.Exception -> L37
        L55:
            int r2 = r4.length()     // Catch: java.lang.Exception -> L37
            if (r2 <= 0) goto L66
            java.lang.String r5 = r4.toString()     // Catch: java.lang.Exception -> L37
            goto L66
        L60:
            java.lang.String r4 = "empty data as SDK not yet initialized "
            r6 = 3
            com.google.android.gms.measurement.internal.Z.n(r4, r2, r0, r6)
        L66:
            boolean r0 = com.onetrust.otpublishers.headless.Internal.a.j(r5)
            if (r0 == 0) goto L6d
            goto L90
        L6d:
            org.json.JSONObject r0 = new org.json.JSONObject
            r0.<init>(r5)
            com.onetrust.otpublishers.headless.Internal.Models.b r2 = new com.onetrust.otpublishers.headless.Internal.Models.b
            r2.<init>(r1)
            boolean r2 = r2.a(r0)
            if (r2 == 0) goto L90
            com.onetrust.otpublishers.headless.Internal.Helper.j r2 = new com.onetrust.otpublishers.headless.Internal.Helper.j
            r2.<init>(r1)
            java.lang.String r1 = "Groups"
            org.json.JSONArray r0 = r0.getJSONArray(r1)
            org.json.JSONObject r1 = new org.json.JSONObject
            r1.<init>()
            r2.i(r0, r1, r3)
        L90:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.d.a():void");
    }

    public final void b(String str, String str2) throws JSONException {
        int length = !com.onetrust.otpublishers.headless.Internal.a.j(str) ? str.length() : -1;
        int length2 = com.onetrust.otpublishers.headless.Internal.a.j(str2) ? -1 : str2.length();
        String string = this.c.a.b().getString("OT_IAB_ACTIVE_VENDORLIST", null);
        JSONObject jSONObject = com.onetrust.otpublishers.headless.Internal.a.j(string) ? null : new JSONObject(string);
        if (jSONObject == null) {
            OTLogger.c("IABTCStringParser", 4, "Empty vendor array, not updating the vendor status. Vendor status will be updated once vendor details fetched.");
            return;
        }
        Iterator<String> itKeys = jSONObject.keys();
        boolean z = false;
        while (itKeys.hasNext()) {
            String next = itKeys.next();
            JSONObject jSONObject2 = jSONObject.getJSONObject(next);
            int i = jSONObject2.getInt("id");
            boolean zD = d(str, length, jSONObject2, i, OTVendorUtils.CONSENT_TYPE);
            boolean zD2 = d(str2, length2, jSONObject2, i, OTVendorUtils.LEGITIMATE_CONSENT_TYPE);
            if (zD || zD2) {
                jSONObject.put(next, jSONObject2);
                z = true;
            }
        }
        if (z) {
            L.i(jSONObject, this.d.b().edit(), "OT_IAB_ACTIVE_VENDORLIST");
        }
    }

    public final void c(String str, String str2, String str3) throws JSONException, NumberFormatException {
        int length = -1;
        int length2 = (str == null || com.onetrust.otpublishers.headless.Internal.a.j(str)) ? -1 : str.length();
        int length3 = (str2 == null || com.onetrust.otpublishers.headless.Internal.a.j(str2)) ? -1 : str2.length();
        if (str3 != null && !com.onetrust.otpublishers.headless.Internal.a.j(str3)) {
            length = str3.length();
        }
        String string = this.c.a.b().getString("OTT_IAB_CONSENTABLE_PURPOSES", "");
        JSONObject jSONObject = !com.onetrust.otpublishers.headless.Internal.a.j(string) ? new JSONObject(string) : null;
        if (jSONObject == null) {
            jSONObject = new JSONObject();
        }
        JSONObject jSONObject2 = new JSONObject();
        JSONObject jSONObject3 = new JSONObject();
        JSONObject jSONObject4 = new JSONObject();
        int i = 1;
        while (true) {
            int i2 = 0;
            if (i > 11) {
                break;
            }
            String strValueOf = String.valueOf(i);
            if (str != null && !com.onetrust.otpublishers.headless.Internal.a.j(str) && i > 0 && i <= length2) {
                i2 = Integer.parseInt(String.valueOf(str.charAt(i - 1)));
            }
            jSONObject2.put(strValueOf, i2);
            i++;
        }
        int i3 = 2;
        while (i3 <= 11) {
            jSONObject3.put(String.valueOf(i3), (str2 == null || com.onetrust.otpublishers.headless.Internal.a.j(str2) || i3 <= 0 || i3 > length3) ? 0 : Integer.parseInt(String.valueOf(str2.charAt(i3 - 1))));
            i3++;
        }
        int i4 = 1;
        while (i4 <= 2) {
            jSONObject4.put(String.valueOf(i4), (str3 == null || com.onetrust.otpublishers.headless.Internal.a.j(str3) || i4 <= 0 || i4 > length) ? 0 : Integer.parseInt(String.valueOf(str3.charAt(i4 - 1))));
            i4++;
        }
        jSONObject.put("purposes", jSONObject2);
        jSONObject.put("purposeLegitimateInterests", jSONObject3);
        jSONObject.put("special_feature_opt_ins", jSONObject4);
        L.i(jSONObject, this.d.b().edit(), "OTT_IAB_CONSENTABLE_PURPOSES");
    }

    /* JADX WARN: Removed duplicated region for block: B:177:0x0483  */
    /* JADX WARN: Removed duplicated region for block: B:184:0x04d2  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x011d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void e() {
        /*
            Method dump skipped, instructions count: 1329
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.d.e():void");
    }
}
