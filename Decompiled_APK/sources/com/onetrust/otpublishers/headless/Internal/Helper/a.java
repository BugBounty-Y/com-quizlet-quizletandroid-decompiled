package com.onetrust.otpublishers.headless.Internal.Helper;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.annotation.NonNull;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Public.uiutils.OTVendorUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class a {
    public final Context a;

    public a(@NonNull Context context) {
        this.a = context;
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x0086 A[Catch: JSONException -> 0x0034, TryCatch #0 {JSONException -> 0x0034, blocks: (B:3:0x0009, B:5:0x000f, B:8:0x0027, B:14:0x003c, B:21:0x006b, B:23:0x0076, B:25:0x007c, B:26:0x0080, B:28:0x0086, B:29:0x008a, B:33:0x0097, B:36:0x00a4, B:38:0x00aa, B:40:0x00b4, B:42:0x00c0, B:43:0x00c3, B:44:0x00c6, B:46:0x00cc, B:48:0x00d2, B:51:0x00e2, B:53:0x00f1, B:52:0x00ee, B:20:0x0066, B:19:0x004f, B:16:0x0048), top: B:58:0x0009, inners: #1 }] */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0092  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0095  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00a3  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x00cc A[Catch: JSONException -> 0x0034, LOOP:1: B:46:0x00cc->B:54:0x00f4, LOOP_START, PHI: r5
  0x00cc: PHI (r5v2 int) = (r5v1 int), (r5v3 int) binds: [B:45:0x00ca, B:54:0x00f4] A[DONT_GENERATE, DONT_INLINE], TryCatch #0 {JSONException -> 0x0034, blocks: (B:3:0x0009, B:5:0x000f, B:8:0x0027, B:14:0x003c, B:21:0x006b, B:23:0x0076, B:25:0x007c, B:26:0x0080, B:28:0x0086, B:29:0x008a, B:33:0x0097, B:36:0x00a4, B:38:0x00aa, B:40:0x00b4, B:42:0x00c0, B:43:0x00c3, B:44:0x00c6, B:46:0x00cc, B:48:0x00d2, B:51:0x00e2, B:53:0x00f1, B:52:0x00ee, B:20:0x0066, B:19:0x004f, B:16:0x0048), top: B:58:0x0009, inners: #1 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void a(android.content.Context r9, com.onetrust.otpublishers.headless.Internal.Preferences.d r10, org.json.JSONObject r11, org.json.JSONObject r12) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 266
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.a.a(android.content.Context, com.onetrust.otpublishers.headless.Internal.Preferences.d, org.json.JSONObject, org.json.JSONObject):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:103:? A[ADDED_TO_REGION, RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0079  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0084  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0098  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x00c1  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x00d5  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x00e1  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x00e5  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00f2  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x00f9  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00fb  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0122  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x01a3  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x01a6 A[Catch: JSONException -> 0x018d, TryCatch #3 {JSONException -> 0x018d, blocks: (B:36:0x00f3, B:53:0x0128, B:57:0x0137, B:60:0x013e, B:71:0x0178, B:73:0x017e, B:75:0x0188, B:78:0x018f, B:80:0x0195, B:70:0x0173, B:69:0x015b, B:85:0x01a6, B:87:0x01b0, B:89:0x01b6, B:42:0x0101, B:48:0x0114, B:64:0x0148, B:66:0x0154), top: B:99:0x00f3, inners: #0 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void b(android.content.Context r17, java.lang.String r18) {
        /*
            Method dump skipped, instructions count: 462
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.a.b(android.content.Context, java.lang.String):void");
    }

    public static void c(SharedPreferences sharedPreferences, com.onetrust.otpublishers.headless.Internal.Preferences.e eVar, boolean z) throws JSONException {
        eVar.getClass();
        JSONObject jSONObject = null;
        try {
            String string = eVar.a.b().getString("OT_GOOGLE_ACTIVE_VENDOR_LIST", null);
            if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                jSONObject = new JSONObject(string);
            }
        } catch (JSONException e) {
            Z.p("error while getting culture data json on getActiveGoogleVendors, err: ", e, "OneTrust", 6);
        }
        if (jSONObject != null) {
            try {
                JSONObject jSONObject2 = new JSONObject();
                String str = z ? "1" : "0";
                JSONArray jSONArrayNames = jSONObject.names();
                if (jSONArrayNames != null) {
                    for (int i = 0; i < jSONArrayNames.length(); i++) {
                        String string2 = jSONArrayNames.getString(i);
                        JSONObject jSONObject3 = jSONObject.getJSONObject(string2);
                        if (jSONObject2.has(string2)) {
                            jSONObject3.put(OTVendorUtils.CONSENT_TYPE, jSONObject2.getJSONObject(string2).getInt(OTVendorUtils.CONSENT_TYPE));
                        } else {
                            jSONObject3.put(OTVendorUtils.CONSENT_TYPE, str);
                        }
                        jSONObject.put(string2, jSONObject3);
                    }
                }
                sharedPreferences.edit().putString("OT_GOOGLE_ACTIVE_VENDOR_LIST", jSONObject.toString()).apply();
            } catch (JSONException e2) {
                Z.p("Error in updating google vendor status. Error message : ", e2, "GoogleVendorHelper", 6);
            }
        }
    }
}
