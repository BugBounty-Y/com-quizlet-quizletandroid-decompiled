package com.onetrust.otpublishers.headless.Internal.Helper;

import android.content.Context;
import android.content.SharedPreferences;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Q;
import com.google.android.gms.internal.mlkit_vision_document_scanner.V;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import java.util.UUID;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class m {
    public final com.onetrust.otpublishers.headless.Internal.Preferences.d a;

    public m(com.onetrust.otpublishers.headless.Internal.Preferences.d dVar) {
        this.a = dVar;
    }

    public static void b(SharedPreferences sharedPreferences, JSONObject jSONObject, com.onetrust.otpublishers.headless.Internal.Models.b bVar) {
        long j;
        if (jSONObject.has("DomainData")) {
            JSONObject jSONObject2 = jSONObject.getJSONObject("DomainData");
            c("culture data : ", jSONObject2.toString());
            sharedPreferences.edit().putString("OTT_CULTURE_DOMAIN_DATA", jSONObject2.toString()).apply();
            if (jSONObject2.has("LastReconsentDate")) {
                String string = bVar.b.getString("OTT_LAST_RE_CONSENT_DATE", String.valueOf(-1L));
                if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                    OTLogger.c("ShowBanner", 4, "Last re-consent date not initialized, it will be set once OT SDK initialized.");
                    j = -1;
                } else {
                    j = Long.parseLong(string);
                }
                if (j == -1) {
                    String string2 = !jSONObject2.isNull("LastReconsentDate") ? jSONObject2.get("LastReconsentDate").toString() : "";
                    OTLogger.c("ShowBanner", 4, "Initializing the last re-consent date to - " + string2);
                    boolean zJ = com.onetrust.otpublishers.headless.Internal.a.j(string2);
                    SharedPreferences sharedPreferences2 = bVar.b;
                    if (zJ || jSONObject2.isNull("LastReconsentDate")) {
                        V.a(sharedPreferences2, "OTT_LAST_RE_CONSENT_DATE", "0");
                    } else {
                        V.a(sharedPreferences2, "OTT_LAST_RE_CONSENT_DATE", string2);
                    }
                }
            }
            sharedPreferences.edit().putBoolean("IS_IAB2_V2_TEMPLATE_FLAG", com.onetrust.otpublishers.headless.Internal.a.l(jSONObject2.optString("IabType"))).apply();
        }
    }

    public static void c(String str, String str2) {
        OTLogger.c("AppDataParser", 3, str + str2);
    }

    public static void d(JSONArray jSONArray, JSONObject jSONObject, int i, boolean z) throws JSONException {
        if (!(jSONObject.getBoolean("IsIabPurpose") && jSONObject.getBoolean("ShowInPopup") && com.quizlet.shared.usecase.srs.a.q(jSONObject, z)) && jSONObject.getJSONArray("FirstPartyCookies").length() <= 0) {
            return;
        }
        if (jSONArray.getJSONObject(i).has("SubGroups")) {
            jSONArray.getJSONObject(i).getJSONArray("SubGroups").put(jSONObject);
            return;
        }
        JSONArray jSONArray2 = new JSONArray();
        jSONArray2.put(jSONObject);
        jSONArray.getJSONObject(i).put("SubGroups", jSONArray2);
    }

    /* JADX WARN: Removed duplicated region for block: B:121:0x0255  */
    /* JADX WARN: Removed duplicated region for block: B:124:0x025c A[PHI: r19
  0x025c: PHI (r19v4 java.lang.String) = (r19v1 java.lang.String), (r19v8 java.lang.String) binds: [B:123:0x025a, B:82:0x01c3] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:125:0x025f A[Catch: JSONException -> 0x0131, PHI: r1 r19
  0x025f: PHI (r1v31 java.lang.String) = (r1v21 java.lang.String), (r1v42 java.lang.String) binds: [B:123:0x025a, B:81:0x01c1] A[DONT_GENERATE, DONT_INLINE]
  0x025f: PHI (r19v3 java.lang.String) = (r19v1 java.lang.String), (r19v8 java.lang.String) binds: [B:123:0x025a, B:81:0x01c1] A[DONT_GENERATE, DONT_INLINE], TryCatch #0 {JSONException -> 0x0131, blocks: (B:36:0x00ff, B:39:0x010b, B:40:0x0110, B:42:0x0116, B:44:0x012a, B:61:0x016d, B:63:0x0173, B:65:0x0179, B:66:0x017e, B:68:0x0184, B:127:0x0265, B:71:0x0196, B:72:0x0199, B:74:0x019f, B:76:0x01a5, B:78:0x01af, B:80:0x01bb, B:125:0x025f, B:84:0x01ca, B:86:0x01d0, B:88:0x01d6, B:89:0x01dd, B:91:0x01e3, B:94:0x01f2, B:96:0x01f7, B:101:0x0204, B:103:0x020a, B:105:0x0210, B:107:0x0216, B:108:0x021b, B:110:0x0221, B:113:0x0231, B:114:0x0234, B:116:0x023a, B:118:0x0240, B:120:0x024a, B:122:0x0256, B:47:0x0134, B:48:0x0139, B:50:0x013f, B:52:0x014d, B:128:0x0276), top: B:132:0x00ff }] */
    /* JADX WARN: Removed duplicated region for block: B:79:0x01ba  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x01c3  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void e(org.json.JSONObject r20, android.content.Context r21, com.onetrust.otpublishers.headless.Internal.Preferences.e r22) {
        /*
            Method dump skipped, instructions count: 684
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.m.e(org.json.JSONObject, android.content.Context, com.onetrust.otpublishers.headless.Internal.Preferences.e):void");
    }

    public static void f(JSONObject jSONObject, JSONArray jSONArray, Context context) {
        boolean z;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        String str;
        boolean z2;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar2;
        androidx.compose.foundation.text.input.internal.u uVar = new androidx.compose.foundation.text.input.internal.u(14);
        com.quizlet.data.repository.login.a aVar = new com.quizlet.data.repository.login.a();
        if (jSONObject.getJSONObject("culture").getJSONObject("CommonData").has("ConsentIntegration")) {
            JSONObject jSONObject2 = jSONObject.getJSONObject("culture").getJSONObject("CommonData").getJSONObject("ConsentIntegration");
            SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
            String str2 = "";
            if (Q.a(context)) {
                fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
                z = true;
            } else {
                z = false;
                fVar = null;
            }
            if (z) {
                sharedPreferences = fVar;
            }
            sharedPreferences.edit().putString("OT_CONSENT_INTEGRATION_DATA", jSONObject2.toString()).apply();
            if (jSONObject2.optString("ConsentApi") != null) {
                SharedPreferences sharedPreferences2 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                if (Q.a(context)) {
                    fVar2 = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences2, sharedPreferences2.getString("OT_ACTIVE_PROFILE_ID", ""));
                    z2 = true;
                } else {
                    z2 = false;
                    fVar2 = null;
                }
                String string = (z2 ? fVar2 : sharedPreferences2).getString("OTT_DATA_SUBJECT_IDENTIFIER", "");
                if (string == null) {
                    string = "";
                }
                if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                    SharedPreferences sharedPreferences3 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                    String string2 = sharedPreferences3.getString("OT_GENERIC_PROFILE_IDENTIFIER", null);
                    if (com.onetrust.otpublishers.headless.Internal.a.j(string2)) {
                        string2 = UUID.randomUUID().toString();
                        V.a(sharedPreferences3, "OT_GENERIC_PROFILE_IDENTIFIER", string2);
                    }
                    str2 = string2;
                    V.a(z2 ? fVar2 : sharedPreferences2, "OTT_DATA_SUBJECT_IDENTIFIER", str2);
                    if (z2) {
                        sharedPreferences2 = fVar2;
                    }
                    sharedPreferences2.edit().putInt("OTT_DATA_SUBJECT_IDENTIFIER_TYPE", 1).apply();
                } else {
                    if (z2) {
                        sharedPreferences2 = fVar2;
                    }
                    String string3 = sharedPreferences2.getString("OTT_DATA_SUBJECT_IDENTIFIER", "");
                    if (string3 != null) {
                        str2 = string3;
                    }
                }
                aVar.c = str2;
                aVar.b = jSONArray;
                aVar.a = jSONObject2.optString("RequestInformation");
                uVar.b = jSONObject2.optString("ConsentApi");
                uVar.c = aVar;
                try {
                    new r(context).b(uVar);
                    return;
                } catch (Exception unused) {
                    str = "could not construct consent logging data";
                }
            } else {
                str = "error while constructing consent payload";
            }
            OTLogger.c("AppDataParser", 4, str);
        }
    }

    public static void g(JSONObject jSONObject, boolean z) {
        JSONArray jSONArray = jSONObject.getJSONObject("culture").getJSONObject("DomainData").getJSONArray("Groups");
        for (int i = 0; i < jSONArray.length(); i++) {
            if (!jSONArray.getJSONObject(i).getString("Parent").isEmpty()) {
                JSONObject jSONObject2 = jSONArray.getJSONObject(i);
                String string = jSONArray.getJSONObject(i).getString("Parent");
                for (int i2 = 0; i2 < jSONArray.length(); i2++) {
                    try {
                        if (string.equals(jSONArray.getJSONObject(i2).optString("CustomGroupId"))) {
                            d(jSONArray, jSONObject2, i2, z);
                        }
                    } catch (JSONException e) {
                        Z.p("error while moving subgroups with err = ", e, "AppDataParser", 6);
                    }
                }
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:19:0x00ad  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x00fe  */
    /* JADX WARN: Type inference failed for: r10v16, types: [com.google.firebase.tracing.a] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(android.content.SharedPreferences r8, org.json.JSONObject r9, android.content.Context r10, com.onetrust.otpublishers.headless.Internal.Preferences.e r11, boolean r12, boolean r13) {
        /*
            Method dump skipped, instructions count: 530
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.m.a(android.content.SharedPreferences, org.json.JSONObject, android.content.Context, com.onetrust.otpublishers.headless.Internal.Preferences.e, boolean, boolean):void");
    }
}
