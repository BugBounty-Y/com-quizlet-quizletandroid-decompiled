package com.google.android.gms.internal.mlkit_vision_document_scanner;

import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public abstract class X {
    public static final /* synthetic */ int a = 0;

    /* JADX WARN: Removed duplicated region for block: B:11:0x007e  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x00e2  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x00ec  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0113  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x01b5  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x011c A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static org.json.JSONObject a(android.content.Context r21, int r22, org.json.JSONObject r23) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 444
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.X.a(android.content.Context, int, org.json.JSONObject):org.json.JSONObject");
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0021  */
    /* JADX WARN: Removed duplicated region for block: B:6:0x0013 A[PHI: r1
  0x0013: PHI (r1v8 java.lang.String) = (r1v2 java.lang.String), (r1v10 java.lang.String) binds: [B:8:0x001e, B:5:0x0011] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void b(android.content.Context r1, com.onetrust.otpublishers.headless.Internal.Preferences.d r2, org.json.JSONObject r3) {
        /*
            com.onetrust.otpublishers.headless.Internal.Preferences.e r0 = new com.onetrust.otpublishers.headless.Internal.Preferences.e
            r0.<init>(r1)
            boolean r1 = r0.m()
            if (r1 == 0) goto L18
            java.lang.String r1 = "Iab2V2Data"
            boolean r0 = r3.has(r1)
            if (r0 == 0) goto L21
        L13:
            org.json.JSONObject r1 = r3.optJSONObject(r1)
            goto L22
        L18:
            java.lang.String r1 = "IabV2Data"
            boolean r0 = r3.has(r1)
            if (r0 == 0) goto L21
            goto L13
        L21:
            r1 = 0
        L22:
            if (r1 == 0) goto L45
            java.lang.String r3 = "vendorListVersion"
            boolean r0 = r1.has(r3)
            if (r0 == 0) goto L45
            java.lang.String r1 = r1.optString(r3)
            int r1 = java.lang.Integer.parseInt(r1)
            android.content.SharedPreferences r2 = r2.b()
            android.content.SharedPreferences$Editor r2 = r2.edit()
            java.lang.String r3 = "OT_DOMAIN_DATA_IAB_VENDOR_LIST_VERSION"
            android.content.SharedPreferences$Editor r1 = r2.putInt(r3, r1)
            r1.apply()
        L45:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.X.b(android.content.Context, com.onetrust.otpublishers.headless.Internal.Preferences.d, org.json.JSONObject):void");
    }

    public static void c(com.onetrust.otpublishers.headless.Internal.Preferences.e eVar, JSONArray jSONArray) {
        JSONObject jSONObject = new JSONObject();
        JSONObject jSONObject2 = new JSONObject();
        JSONObject jSONObject3 = new JSONObject();
        JSONObject jSONObject4 = new JSONObject();
        JSONObject jSONObject5 = new JSONObject();
        for (int i = 0; i < jSONArray.length(); i++) {
            JSONObject jSONObject6 = jSONArray.getJSONObject(i);
            if (jSONObject6.getBoolean("IsIabPurpose")) {
                String strQ = com.onetrust.otpublishers.headless.Internal.Helper.c.q(jSONObject6.optString("CustomGroupId", "-1"));
                String string = jSONObject6.getString("Type");
                String string2 = jSONObject6.getString("GroupName");
                if (string.equals("IAB2_PURPOSE") || string.equals("IAB2V2_PURPOSE")) {
                    JSONObject jSONObject7 = new JSONObject();
                    jSONObject7.put("id", strQ);
                    jSONObject7.put("name", string2);
                    jSONObject4.put(strQ, jSONObject7);
                }
                if (string.equals("IAB2_FEATURE") || string.equals("IAB2V2_FEATURE")) {
                    JSONObject jSONObject8 = new JSONObject();
                    jSONObject8.put("id", strQ);
                    jSONObject8.put("name", string2);
                    jSONObject2.put(strQ, jSONObject8);
                }
                if (string.equals("IAB2_SPL_PURPOSE") || string.equals("IAB2V2_SPL_PURPOSE")) {
                    JSONObject jSONObject9 = new JSONObject();
                    jSONObject9.put("id", strQ);
                    jSONObject9.put("name", string2);
                    jSONObject5.put(strQ, jSONObject9);
                }
                if (string.equals("IAB2_SPL_FEATURE") || string.equals("IAB2V2_SPL_FEATURE")) {
                    JSONObject jSONObject10 = new JSONObject();
                    jSONObject10.put("id", strQ);
                    jSONObject10.put("name", string2);
                    jSONObject3.put(strQ, jSONObject10);
                }
            }
        }
        jSONObject.put("features", jSONObject2);
        jSONObject.put("purposes", jSONObject4);
        jSONObject.put("specialFeatures", jSONObject3);
        jSONObject.put("specialPurposes", jSONObject5);
        eVar.a.b().edit().putString("OT_IAB_PURPOSES_TRANSLATED", jSONObject.toString()).apply();
    }

    public static void d(String str, JSONObject jSONObject, JSONObject jSONObject2) throws JSONException {
        String str2;
        OTLogger.c("VendorUtils", 2, "getting details of " + str + "from GVL");
        JSONArray jSONArray = new JSONArray();
        if (str.equals("legIntPurposes") || str.equals("flexiblePurposes")) {
            OTLogger.c("VendorUtils", 2, "contains legIntPurposes/flexiblePurposes details");
            str2 = "purposes";
        } else {
            str2 = str;
        }
        JSONObject jSONObject3 = new JSONObject();
        if (jSONObject.has(str2)) {
            jSONObject3 = jSONObject.getJSONObject(str2);
        }
        JSONArray jSONArray2 = new JSONArray();
        if (jSONObject2.has(str)) {
            jSONArray2 = jSONObject2.getJSONArray(str);
        }
        for (int i = 0; i < jSONArray2.length(); i++) {
            String string = jSONArray2.get(i).toString();
            if (jSONObject3.has(string)) {
                jSONArray.put(jSONObject3.get(string));
            }
        }
        jSONObject2.put(str, jSONArray);
    }
}
