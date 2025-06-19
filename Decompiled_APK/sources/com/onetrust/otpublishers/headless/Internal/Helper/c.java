package com.onetrust.otpublishers.headless.Internal.Helper;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3605e0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.L;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Q;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.Keys.OTIABTCFKeys;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import com.onetrust.otpublishers.headless.Public.uiutils.OTVendorUtils;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class c {
    public final Context a;

    public c(@NonNull Context context) {
        this.a = context;
    }

    public static String c(OTPublishersHeadlessSDK oTPublishersHeadlessSDK, JSONObject jSONObject, JSONObject jSONObject2) throws JSONException {
        HashMap map = new HashMap();
        HashMap map2 = new HashMap();
        String strOptString = jSONObject.optString("CustomGroupId");
        try {
            if (!jSONObject.optString("Type").equalsIgnoreCase("IAB2_STACK") && !jSONObject.optString("Type").equalsIgnoreCase("IAB2V2_STACK") && jSONObject.getBoolean("IsIabPurpose")) {
                map.put(strOptString, jSONObject.optString("Type", ""));
            }
            m(map, jSONObject, map2);
            if (!map2.isEmpty()) {
                for (Map.Entry entry : map2.entrySet()) {
                    HashMap map3 = new HashMap();
                    map3.put((String) entry.getKey(), (String) entry.getValue());
                    String str = (String) entry.getKey();
                    JSONObject vendorsByPurpose = !map3.isEmpty() ? oTPublishersHeadlessSDK.getOtVendorUtils().getVendorsByPurpose(map3, oTPublishersHeadlessSDK.getVendorListUI(OTVendorListMode.IAB)) : null;
                    jSONObject2.put(str, vendorsByPurpose != null ? String.valueOf(vendorsByPurpose.length()) : "");
                }
            }
            JSONObject vendorsByPurpose2 = map.isEmpty() ? null : oTPublishersHeadlessSDK.getOtVendorUtils().getVendorsByPurpose(map, oTPublishersHeadlessSDK.getVendorListUI(OTVendorListMode.IAB));
            return vendorsByPurpose2 != null ? String.valueOf(vendorsByPurpose2.length()) : "";
        } catch (JSONException e) {
            Z.p("error in parsing vendor list link on setCategoriesForVendorList, returning empty string.", e, "IABHelper", 6);
            return "";
        }
    }

    public static Date d(com.onetrust.otpublishers.headless.Internal.Preferences.d dVar) {
        Date date = new Date();
        Date date2 = new Date(date.getTime() - (date.getTime() % 86400000));
        SharedPreferences.Editor editorEdit = dVar.b().edit();
        editorEdit.putString("OT_IAB_TCStr_LastUpdated", date2.toString());
        editorEdit.putLong("OT_IAB_TC_STR_LAST_UPDATED_IN_MILLISECONDS", date2.getTime()).apply();
        OTLogger.c("IABHelper", 3, "Tc string updating date timestamp = " + date2.getTime());
        return date2;
    }

    public static JSONArray f(JSONObject jSONObject) {
        JSONArray jSONArray = new JSONArray();
        for (int i = 0; i < jSONObject.length(); i++) {
            try {
                if (jSONObject.getInt(jSONObject.names().get(i).toString()) != 0) {
                    jSONArray.put(Integer.parseInt(jSONObject.names().get(i).toString()));
                }
            } catch (Exception e) {
                Z.n("error in getting purpose ids : ", e, "IABHelper", 6);
            }
        }
        OTLogger.c("IABHelper", 3, "purposes consent " + jSONArray.toString());
        return jSONArray;
    }

    public static void i(com.onetrust.otpublishers.headless.Internal.Preferences.d dVar, Date date) {
        SharedPreferences.Editor editorEdit = dVar.b().edit();
        editorEdit.putString("OT_IAB_TCStr_Created", date.toString());
        editorEdit.putLong("OT_IAB_TC_STR_CREATED_IN_MILLISECONDS", date.getTime()).apply();
        OTLogger.c("IABHelper", 3, "Tc string Created date timestamp = " + date.getTime());
    }

    public static void j(com.onetrust.otpublishers.headless.Internal.Preferences.d dVar, boolean z, JSONObject jSONObject, JSONObject jSONObject2, JSONObject jSONObject3, String str) throws JSONException {
        String str2;
        JSONArray jSONArray;
        int i;
        boolean z2;
        boolean z3;
        int i2;
        if (jSONObject3.length() > 0) {
            OTLogger.c("IABHelper", 3, "domain id contains overridden vendors");
            JSONArray jSONArrayNames = jSONObject3.names();
            if (jSONArrayNames != null) {
                int i3 = 0;
                while (i3 < jSONArrayNames.length()) {
                    String string = jSONArrayNames.getString(i3);
                    if (jSONObject2.has(string)) {
                        JSONObject jSONObject4 = jSONObject3.getJSONObject(string);
                        if (jSONObject4.getBoolean("active")) {
                            JSONObject jSONObject5 = jSONObject2.getJSONObject(string);
                            if (jSONObject4.has("disabledCP") && jSONObject5.has("purposes")) {
                                JSONArray jSONArray2 = jSONObject4.getJSONArray("disabledCP");
                                JSONArray jSONArray3 = jSONObject5.getJSONArray("purposes");
                                jSONArray = jSONArrayNames;
                                int i4 = 0;
                                z2 = false;
                                while (i4 < jSONArray2.length()) {
                                    int i5 = jSONArray2.getInt(i4);
                                    int i6 = i4;
                                    int i7 = i3;
                                    int i8 = 0;
                                    while (true) {
                                        if (i8 >= jSONArray3.length()) {
                                            i8 = -1;
                                            break;
                                        } else if (i5 == jSONArray3.getInt(i8)) {
                                            break;
                                        } else {
                                            i8++;
                                        }
                                    }
                                    if (i8 > -1) {
                                        jSONArray3.remove(i8);
                                        z2 = true;
                                    }
                                    i4 = i6 + 1;
                                    i3 = i7;
                                }
                                i = i3;
                                if (z2) {
                                    jSONObject5.put("purposes", jSONArray3);
                                }
                            } else {
                                jSONArray = jSONArrayNames;
                                i = i3;
                                z2 = false;
                            }
                            if (jSONObject4.has("disabledLIP") && jSONObject5.has("legIntPurposes")) {
                                JSONArray jSONArray4 = jSONObject4.getJSONArray("disabledLIP");
                                JSONArray jSONArray5 = jSONObject5.getJSONArray("legIntPurposes");
                                int i9 = 0;
                                z3 = false;
                                while (i9 < jSONArray4.length()) {
                                    int i10 = jSONArray4.getInt(i9);
                                    JSONArray jSONArray6 = jSONArray4;
                                    int i11 = 0;
                                    while (true) {
                                        if (i11 >= jSONArray5.length()) {
                                            i2 = -1;
                                            break;
                                        } else {
                                            if (i10 == jSONArray5.getInt(i11)) {
                                                i2 = i11;
                                                break;
                                            }
                                            i11++;
                                        }
                                    }
                                    if (i2 > -1) {
                                        jSONArray5.remove(i2);
                                        z3 = true;
                                    }
                                    i9++;
                                    jSONArray4 = jSONArray6;
                                }
                                if (z3) {
                                    jSONObject5.put("legIntPurposes", jSONArray5);
                                }
                            } else {
                                z3 = false;
                            }
                            if (z2 || z3) {
                                jSONObject2.put(string, jSONObject5);
                            }
                        } else {
                            jSONObject2.remove(string);
                            jSONArray = jSONArrayNames;
                            i = i3;
                        }
                    } else {
                        jSONArray = jSONArrayNames;
                        i = i3;
                    }
                    i3 = i + 1;
                    jSONArrayNames = jSONArray;
                }
                p(jSONObject2, jSONObject, jSONObject3, str, z);
            }
            OTLogger.c("IABHelper", 4, "IAB TCF Active Vendor list, applied overridden  vendors rules : " + jSONObject2.length() + " " + jSONObject2);
            str2 = "IAB TCF Active Vendor list,  applied toggle state";
        } else {
            OTLogger.c("IABHelper", 3, "domain id using global vendor list");
            p(jSONObject2, jSONObject, jSONObject3, str, z);
            str2 = "IAB TCF Active Vendor list : " + jSONObject2.length() + " " + jSONObject2.toString();
        }
        OTLogger.c("IABHelper", 4, str2);
        dVar.b().edit().putString("OT_IAB_ACTIVE_VENDORLIST", jSONObject2.toString()).apply();
        if (com.onetrust.otpublishers.headless.Internal.a.j(dVar.b().getString("OT_IAB_DEFAULT_AVL", ""))) {
            L.i(jSONObject2, dVar.b().edit(), "OT_IAB_DEFAULT_AVL");
        }
    }

    public static void l(String str, JSONArray jSONArray, JSONArray jSONArray2, JSONObject jSONObject, String str2, boolean z) {
        if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            if (jSONObject.getInt(OTVendorUtils.CONSENT_TYPE) == 1) {
                jSONArray.put(Integer.parseInt(str2));
            }
        } else if (jSONObject.getInt(OTVendorUtils.LEGITIMATE_CONSENT_TYPE) == 1 || (jSONObject.getJSONArray("purposes").length() == 0 && jSONObject.getJSONArray("legIntPurposes").length() == 0 && jSONObject.getJSONArray("specialPurposes").length() > 0 && z)) {
            jSONArray2.put(Integer.parseInt(str2));
        }
    }

    public static void m(HashMap map, JSONObject jSONObject, HashMap map2) throws JSONException {
        if (jSONObject.has("SubGroups")) {
            JSONArray jSONArray = jSONObject.getJSONArray("SubGroups");
            int length = jSONArray.length();
            for (int i = 0; i < length; i++) {
                JSONObject jSONObject2 = jSONArray.getJSONObject(i);
                if (jSONObject2.getBoolean("IsIabPurpose")) {
                    map.put(jSONObject2.getString("CustomGroupId"), jSONObject2.getString("Type"));
                    map2.put(jSONObject2.getString("CustomGroupId"), jSONObject2.getString("Type"));
                }
            }
        }
    }

    public static void n(JSONObject jSONObject, String str) throws JSONException {
        OTLogger.c("IABHelper", 4, str);
        JSONArray jSONArrayNames = jSONObject.names();
        if (jSONArrayNames != null) {
            for (int i = 0; i < jSONArrayNames.length(); i++) {
                try {
                    String string = jSONArrayNames.getString(i);
                    OTLogger.c("IABHelper", 4, string + ": " + jSONObject.getString(string));
                } catch (JSONException e) {
                    Z.p("error while logging IAB encoder details : ", e, "IABHelper", 5);
                }
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:52:0x00ae A[PHI: r10 r11 r13
  0x00ae: PHI (r10v2 org.json.JSONObject) = (r10v1 org.json.JSONObject), (r10v4 org.json.JSONObject) binds: [B:51:0x00ac, B:35:0x007a] A[DONT_GENERATE, DONT_INLINE]
  0x00ae: PHI (r11v2 java.lang.String) = (r11v1 java.lang.String), (r11v3 java.lang.String) binds: [B:51:0x00ac, B:35:0x007a] A[DONT_GENERATE, DONT_INLINE]
  0x00ae: PHI (r13v1 org.json.JSONArray) = (r13v0 org.json.JSONArray), (r13v3 org.json.JSONArray) binds: [B:51:0x00ac, B:35:0x007a] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void o(org.json.JSONObject r16, org.json.JSONObject r17) throws org.json.JSONException, java.lang.NumberFormatException {
        /*
            r0 = r17
            int r1 = r16.length()
            if (r1 <= 0) goto Lbf
            java.lang.String r1 = "domain id contains publisher restriction."
            java.lang.String r2 = "IABHelper"
            r3 = 3
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r2, r3, r1)
            org.json.JSONArray r1 = r16.names()
            if (r1 == 0) goto Lbf
            r3 = 0
        L17:
            int r4 = r1.length()
            if (r3 >= r4) goto Lbf
            java.lang.String r4 = r1.getString(r3)
            r5 = r16
            org.json.JSONObject r6 = r5.getJSONObject(r4)
            int r7 = r6.length()
            if (r7 != 0) goto L2f
            goto Lbb
        L2f:
            org.json.JSONArray r7 = r6.names()
            if (r7 != 0) goto L37
            goto Lbb
        L37:
            r8 = 0
        L38:
            int r9 = r7.length()
            if (r8 >= r9) goto Lbb
            java.lang.String r9 = r7.getString(r8)
            int r10 = r6.getInt(r9)
            if (r10 != 0) goto L4a
            goto Lb7
        L4a:
            r11 = 1
            r12 = -1
            if (r10 != r11) goto L7d
            boolean r10 = r0.has(r9)
            if (r10 == 0) goto Lb7
            org.json.JSONObject r10 = r0.getJSONObject(r9)
            java.lang.String r11 = "purposes"
            boolean r13 = r10.has(r11)
            if (r13 == 0) goto Lb7
            org.json.JSONArray r13 = r10.getJSONArray(r11)
            int r14 = java.lang.Integer.parseInt(r4)
            r15 = 0
        L69:
            int r2 = r13.length()
            if (r15 >= r2) goto L79
            int r2 = r13.getInt(r15)
            if (r14 != r2) goto L76
            goto L7a
        L76:
            int r15 = r15 + 1
            goto L69
        L79:
            r15 = r12
        L7a:
            if (r15 != r12) goto Lb7
            goto Lae
        L7d:
            r2 = 2
            if (r10 != r2) goto Lb7
            boolean r2 = r0.has(r9)
            if (r2 == 0) goto Lb7
            org.json.JSONObject r10 = r0.getJSONObject(r9)
            java.lang.String r11 = "legIntPurposes"
            boolean r2 = r10.has(r11)
            if (r2 == 0) goto Lb7
            org.json.JSONArray r13 = r10.getJSONArray(r11)
            int r2 = java.lang.Integer.parseInt(r4)
            r14 = 0
        L9b:
            int r15 = r13.length()
            if (r14 >= r15) goto Lab
            int r15 = r13.getInt(r14)
            if (r2 != r15) goto La8
            goto Lac
        La8:
            int r14 = r14 + 1
            goto L9b
        Lab:
            r14 = r12
        Lac:
            if (r14 != r12) goto Lb7
        Lae:
            r13.put(r4)
            r10.put(r11, r13)
            r0.put(r9, r10)
        Lb7:
            int r8 = r8 + 1
            goto L38
        Lbb:
            int r3 = r3 + 1
            goto L17
        Lbf:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.c.o(org.json.JSONObject, org.json.JSONObject):void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:17:0x0080  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0099 A[PHI: r7
  0x0099: PHI (r7v25 int) = (r7v30 int), (r7v31 int) binds: [B:34:0x00d9, B:21:0x0097] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:51:0x0123 A[PHI: r7
  0x0123: PHI (r7v10 int) = (r7v42 int), (r7v43 int), (r7v44 int) binds: [B:67:0x0177, B:64:0x0168, B:50:0x0121] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:69:0x017a A[PHI: r7
  0x017a: PHI (r7v8 int) = (r7v48 int), (r7v49 int), (r7v50 int) binds: [B:67:0x0177, B:64:0x0168, B:50:0x0121] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void p(org.json.JSONObject r16, org.json.JSONObject r17, org.json.JSONObject r18, java.lang.String r19, boolean r20) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 408
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.c.p(org.json.JSONObject, org.json.JSONObject, org.json.JSONObject, java.lang.String, boolean):void");
    }

    public static String q(String str) {
        try {
            return str.contains("_") ? str.split("_")[1] : "";
        } catch (Exception e) {
            Z.n("error while getting the iab group id ", e, "IABHelper", 6);
            return "";
        }
    }

    public static JSONArray r(JSONObject jSONObject) {
        JSONArray jSONArray = new JSONArray();
        for (int i = 0; i < jSONObject.length(); i++) {
            try {
                if (jSONObject.getInt(jSONObject.names().get(i).toString()) != 0) {
                    jSONArray.put(Integer.parseInt(jSONObject.names().get(i).toString()));
                }
            } catch (Exception e) {
                Z.n("error in getting legInt ids : ", e, "IABHelper", 6);
            }
        }
        OTLogger.c("IABHelper", 3, "legInt consent " + jSONArray.toString());
        return jSONArray;
    }

    public static JSONArray u(JSONObject jSONObject) {
        JSONArray jSONArray = new JSONArray();
        for (int i = 0; i < jSONObject.length(); i++) {
            try {
                if (jSONObject.getInt(jSONObject.names().get(i).toString()) != 0) {
                    jSONArray.put(Integer.parseInt(jSONObject.names().get(i).toString()));
                }
            } catch (Exception e) {
                Z.n("error in getting specialFeatureOptIns ids : ", e, "IABHelper", 6);
            }
        }
        OTLogger.c("IABHelper", 3, "specialFeatureOptIns consent " + jSONArray.toString());
        return jSONArray;
    }

    public static int v(String str) throws NumberFormatException {
        OTLogger.c("IABHelper", 3, "active vendorList = " + str);
        int i = 0;
        if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            return 0;
        }
        JSONArray jSONArrayNames = new JSONObject(str).names();
        if (jSONArrayNames != null) {
            int i2 = 0;
            while (i < jSONArrayNames.length()) {
                int i3 = Integer.parseInt(jSONArrayNames.getString(i));
                if (i3 > i2) {
                    i2 = i3;
                }
                i++;
            }
            i = i2;
        }
        OTLogger.c("IABHelper", 4, "maximumVendorId = " + i);
        return i;
    }

    public static String w(JSONObject jSONObject) throws JSONException {
        JSONObject jSONObject2 = new JSONObject();
        if (!jSONObject.has("Language") || jSONObject.isNull("Language")) {
            return "en";
        }
        try {
            jSONObject2 = jSONObject.getJSONObject("Language");
        } catch (JSONException e) {
            Z.o("Error while getting lang, err", e, "IABHelper");
        }
        String strOptString = com.onetrust.otpublishers.headless.Internal.a.j(jSONObject2.optString("Culture")) ? "en" : jSONObject2.optString("Culture");
        return (strOptString.length() <= 2 || !strOptString.contains("-")) ? strOptString : strOptString.split("-")[0].toLowerCase(Locale.ENGLISH);
    }

    public final int a(String str, String str2, String str3, com.onetrust.otpublishers.headless.Internal.Preferences.d dVar, boolean z, JSONObject jSONObject) {
        boolean zA;
        String string = dVar.b().getString("OTT_IAB_CONSENTABLE_PURPOSES", "");
        try {
            zA = new com.onetrust.otpublishers.headless.Internal.Models.b(this.a).a(jSONObject);
        } catch (JSONException e) {
            W.a("error on checking reconsent for IAB status, ", e, "IABHelper", 3);
            zA = false;
        }
        boolean zEqualsIgnoreCase = "active".equalsIgnoreCase(str3);
        try {
            if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                return zEqualsIgnoreCase ? 1 : 0;
            }
            JSONObject jSONObject2 = new JSONObject(string);
            if (jSONObject2.getJSONObject(str2).has(str)) {
                return !zA ? jSONObject2.getJSONObject(str2).getInt(str) : zEqualsIgnoreCase ? 1 : 0;
            }
            if (z) {
                return zEqualsIgnoreCase ? 1 : 0;
            }
            return -1;
        } catch (JSONException e2) {
            W.a("unable to get iab consent status", e2, "IABHelper", 3);
            return zEqualsIgnoreCase ? 1 : 0;
        }
    }

    public final String b() {
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
        String string = sharedPreferences.getString("OT_IAB_ACTIVE_VENDORLIST", "");
        OTLogger.c("IABHelper", 3, !com.onetrust.otpublishers.headless.Internal.a.j(string) ? AbstractC0147y.d("Saved IAB Active Vendor List : ", string) : "Vendor List is empty");
        return string;
    }

    /* JADX WARN: Removed duplicated region for block: B:39:0x00cc  */
    /* JADX WARN: Removed duplicated region for block: B:50:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final org.json.JSONArray e(java.lang.String r11) throws org.json.JSONException {
        /*
            r10 = this;
            java.lang.String r1 = "IABHelper"
            org.json.JSONArray r3 = new org.json.JSONArray
            r3.<init>()
            org.json.JSONArray r4 = new org.json.JSONArray
            r4.<init>()
            android.content.Context r0 = r10.a
            java.lang.String r2 = "com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER"
            r5 = 0
            android.content.SharedPreferences r2 = r0.getSharedPreferences(r2, r5)
            boolean r6 = com.google.android.gms.internal.mlkit_vision_document_scanner.Q.a(r0)
            r7 = 1
            java.lang.String r8 = ""
            if (r6 == 0) goto L2b
            java.lang.String r6 = "OT_ACTIVE_PROFILE_ID"
            java.lang.String r6 = r2.getString(r6, r8)
            com.onetrust.otpublishers.headless.Internal.Preferences.f r9 = new com.onetrust.otpublishers.headless.Internal.Preferences.f
            r9.<init>(r0, r2, r6)
            r0 = r7
            goto L2d
        L2b:
            r9 = 0
            r0 = r5
        L2d:
            if (r0 == 0) goto L30
            r2 = r9
        L30:
            java.lang.String r0 = "OTT_CULTURE_DOMAIN_DATA"
            java.lang.String r0 = r2.getString(r0, r8)
            boolean r2 = com.onetrust.otpublishers.headless.Internal.a.j(r0)
            r8 = 6
            if (r2 != 0) goto L4b
            org.json.JSONObject r2 = new org.json.JSONObject     // Catch: org.json.JSONException -> L43
            r2.<init>(r0)     // Catch: org.json.JSONException -> L43
            goto L50
        L43:
            r0 = move-exception
            java.lang.String r2 = "error while returning culture domain data, err: "
            java.lang.String r6 = "OneTrust"
            com.google.android.gms.measurement.internal.Z.p(r2, r0, r6, r8)
        L4b:
            org.json.JSONObject r2 = new org.json.JSONObject
            r2.<init>()
        L50:
            java.lang.String r0 = "LegIntSettings"
            boolean r6 = r2.isNull(r0)     // Catch: java.lang.Exception -> L9c
            if (r6 != 0) goto L6c
            org.json.JSONObject r6 = r2.getJSONObject(r0)     // Catch: java.lang.Exception -> L9c
            java.lang.String r9 = "PAllowLI"
            boolean r6 = r6.has(r9)     // Catch: java.lang.Exception -> L9c
            if (r6 == 0) goto L6c
            org.json.JSONObject r0 = r2.getJSONObject(r0)     // Catch: java.lang.Exception -> L9c
            boolean r7 = r0.getBoolean(r9)     // Catch: java.lang.Exception -> L9c
        L6c:
            org.json.JSONObject r0 = new org.json.JSONObject     // Catch: java.lang.Exception -> L97
            java.lang.String r2 = r10.b()     // Catch: java.lang.Exception -> L97
            r0.<init>(r2)     // Catch: java.lang.Exception -> L97
            r9 = r5
        L76:
            int r2 = r0.length()     // Catch: java.lang.Exception -> L97
            if (r9 >= r2) goto L9a
            org.json.JSONArray r2 = r0.names()     // Catch: java.lang.Exception -> L97
            java.lang.Object r2 = r2.get(r9)     // Catch: java.lang.Exception -> L97
            java.lang.String r6 = r2.toString()     // Catch: java.lang.Exception -> L97
            org.json.JSONObject r5 = r0.getJSONObject(r6)     // Catch: java.lang.Exception -> L97
            r2 = r11
            l(r2, r3, r4, r5, r6, r7)     // Catch: java.lang.Exception -> L94
            int r9 = r9 + 1
            r11 = r2
            goto L76
        L94:
            r0 = move-exception
        L95:
            r11 = r0
            goto L9e
        L97:
            r0 = move-exception
        L98:
            r2 = r11
            goto L95
        L9a:
            r2 = r11
            goto La3
        L9c:
            r0 = move-exception
            goto L98
        L9e:
            java.lang.String r0 = "error in getting vendor ids : "
            com.google.android.gms.measurement.internal.Z.n(r0, r11, r1, r8)
        La3:
            java.lang.StringBuilder r11 = new java.lang.StringBuilder
            java.lang.String r0 = "vendor consent "
            r11.<init>(r0)
            java.lang.String r0 = r3.toString()
            r11.append(r0)
            java.lang.String r0 = "vendor legInt "
            r11.append(r0)
            java.lang.String r0 = r4.toString()
            r11.append(r0)
            java.lang.String r11 = r11.toString()
            r0 = 3
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r1, r0, r11)
            boolean r11 = com.onetrust.otpublishers.headless.Internal.a.j(r2)
            if (r11 == 0) goto Lcc
            goto Lcd
        Lcc:
            r3 = r4
        Lcd:
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.c.e(java.lang.String):org.json.JSONArray");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:104:0x031b A[Catch: Exception -> 0x02d8, TryCatch #3 {Exception -> 0x02d8, blocks: (B:67:0x0227, B:70:0x026d, B:78:0x0299, B:81:0x02ac, B:110:0x032e, B:114:0x033e, B:116:0x034a, B:121:0x035b, B:123:0x0371, B:125:0x0380, B:128:0x0388, B:130:0x0391, B:132:0x03a2, B:134:0x03cb, B:135:0x03ce, B:137:0x03e4, B:140:0x03f3, B:131:0x039a, B:84:0x02b6, B:85:0x02bb, B:87:0x02cd, B:97:0x02ff, B:99:0x0305, B:101:0x0311, B:102:0x0315, B:104:0x031b, B:96:0x02f9, B:95:0x02e2, B:73:0x0274, B:76:0x0285), top: B:155:0x0227, inners: #0, #6 }] */
    /* JADX WARN: Removed duplicated region for block: B:107:0x0329  */
    /* JADX WARN: Removed duplicated region for block: B:108:0x032b  */
    /* JADX WARN: Removed duplicated region for block: B:112:0x033b  */
    /* JADX WARN: Removed duplicated region for block: B:113:0x033d  */
    /* JADX WARN: Removed duplicated region for block: B:116:0x034a A[Catch: Exception -> 0x02d8, TryCatch #3 {Exception -> 0x02d8, blocks: (B:67:0x0227, B:70:0x026d, B:78:0x0299, B:81:0x02ac, B:110:0x032e, B:114:0x033e, B:116:0x034a, B:121:0x035b, B:123:0x0371, B:125:0x0380, B:128:0x0388, B:130:0x0391, B:132:0x03a2, B:134:0x03cb, B:135:0x03ce, B:137:0x03e4, B:140:0x03f3, B:131:0x039a, B:84:0x02b6, B:85:0x02bb, B:87:0x02cd, B:97:0x02ff, B:99:0x0305, B:101:0x0311, B:102:0x0315, B:104:0x031b, B:96:0x02f9, B:95:0x02e2, B:73:0x0274, B:76:0x0285), top: B:155:0x0227, inners: #0, #6 }] */
    /* JADX WARN: Removed duplicated region for block: B:117:0x0354  */
    /* JADX WARN: Removed duplicated region for block: B:119:0x0357 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:120:0x0359 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:123:0x0371 A[Catch: Exception -> 0x02d8, TryCatch #3 {Exception -> 0x02d8, blocks: (B:67:0x0227, B:70:0x026d, B:78:0x0299, B:81:0x02ac, B:110:0x032e, B:114:0x033e, B:116:0x034a, B:121:0x035b, B:123:0x0371, B:125:0x0380, B:128:0x0388, B:130:0x0391, B:132:0x03a2, B:134:0x03cb, B:135:0x03ce, B:137:0x03e4, B:140:0x03f3, B:131:0x039a, B:84:0x02b6, B:85:0x02bb, B:87:0x02cd, B:97:0x02ff, B:99:0x0305, B:101:0x0311, B:102:0x0315, B:104:0x031b, B:96:0x02f9, B:95:0x02e2, B:73:0x0274, B:76:0x0285), top: B:155:0x0227, inners: #0, #6 }] */
    /* JADX WARN: Removed duplicated region for block: B:124:0x037e  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x0387  */
    /* JADX WARN: Removed duplicated region for block: B:130:0x0391 A[Catch: Exception -> 0x02d8, TryCatch #3 {Exception -> 0x02d8, blocks: (B:67:0x0227, B:70:0x026d, B:78:0x0299, B:81:0x02ac, B:110:0x032e, B:114:0x033e, B:116:0x034a, B:121:0x035b, B:123:0x0371, B:125:0x0380, B:128:0x0388, B:130:0x0391, B:132:0x03a2, B:134:0x03cb, B:135:0x03ce, B:137:0x03e4, B:140:0x03f3, B:131:0x039a, B:84:0x02b6, B:85:0x02bb, B:87:0x02cd, B:97:0x02ff, B:99:0x0305, B:101:0x0311, B:102:0x0315, B:104:0x031b, B:96:0x02f9, B:95:0x02e2, B:73:0x0274, B:76:0x0285), top: B:155:0x0227, inners: #0, #6 }] */
    /* JADX WARN: Removed duplicated region for block: B:131:0x039a A[Catch: Exception -> 0x02d8, TryCatch #3 {Exception -> 0x02d8, blocks: (B:67:0x0227, B:70:0x026d, B:78:0x0299, B:81:0x02ac, B:110:0x032e, B:114:0x033e, B:116:0x034a, B:121:0x035b, B:123:0x0371, B:125:0x0380, B:128:0x0388, B:130:0x0391, B:132:0x03a2, B:134:0x03cb, B:135:0x03ce, B:137:0x03e4, B:140:0x03f3, B:131:0x039a, B:84:0x02b6, B:85:0x02bb, B:87:0x02cd, B:97:0x02ff, B:99:0x0305, B:101:0x0311, B:102:0x0315, B:104:0x031b, B:96:0x02f9, B:95:0x02e2, B:73:0x0274, B:76:0x0285), top: B:155:0x0227, inners: #0, #6 }] */
    /* JADX WARN: Removed duplicated region for block: B:134:0x03cb A[Catch: Exception -> 0x02d8, TryCatch #3 {Exception -> 0x02d8, blocks: (B:67:0x0227, B:70:0x026d, B:78:0x0299, B:81:0x02ac, B:110:0x032e, B:114:0x033e, B:116:0x034a, B:121:0x035b, B:123:0x0371, B:125:0x0380, B:128:0x0388, B:130:0x0391, B:132:0x03a2, B:134:0x03cb, B:135:0x03ce, B:137:0x03e4, B:140:0x03f3, B:131:0x039a, B:84:0x02b6, B:85:0x02bb, B:87:0x02cd, B:97:0x02ff, B:99:0x0305, B:101:0x0311, B:102:0x0315, B:104:0x031b, B:96:0x02f9, B:95:0x02e2, B:73:0x0274, B:76:0x0285), top: B:155:0x0227, inners: #0, #6 }] */
    /* JADX WARN: Removed duplicated region for block: B:144:0x0426 A[Catch: Exception -> 0x0439, TRY_LEAVE, TryCatch #1 {Exception -> 0x0439, blocks: (B:142:0x040b, B:144:0x0426), top: B:151:0x040b }] */
    /* JADX WARN: Removed duplicated region for block: B:149:0x03e4 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:157:0x00e1 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:15:0x00a2  */
    /* JADX WARN: Removed duplicated region for block: B:169:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:19:0x00c0 A[Catch: Exception -> 0x0052, TRY_ENTER, TryCatch #7 {Exception -> 0x0052, blocks: (B:3:0x0021, B:6:0x004c, B:13:0x0076, B:16:0x00a4, B:19:0x00c0, B:23:0x00d5, B:25:0x00e1, B:39:0x0113, B:40:0x011a, B:46:0x0143, B:47:0x0162, B:44:0x0125, B:48:0x0167, B:50:0x0179, B:52:0x017f, B:54:0x018c, B:56:0x0192, B:58:0x019d, B:60:0x01b6, B:62:0x01cd, B:64:0x01d7, B:65:0x01db, B:59:0x01a5, B:12:0x0071, B:11:0x0059), top: B:163:0x0021, inners: #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:20:0x00ce  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x00d4  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x010a  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0120  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0179 A[Catch: Exception -> 0x0052, TryCatch #7 {Exception -> 0x0052, blocks: (B:3:0x0021, B:6:0x004c, B:13:0x0076, B:16:0x00a4, B:19:0x00c0, B:23:0x00d5, B:25:0x00e1, B:39:0x0113, B:40:0x011a, B:46:0x0143, B:47:0x0162, B:44:0x0125, B:48:0x0167, B:50:0x0179, B:52:0x017f, B:54:0x018c, B:56:0x0192, B:58:0x019d, B:60:0x01b6, B:62:0x01cd, B:64:0x01d7, B:65:0x01db, B:59:0x01a5, B:12:0x0071, B:11:0x0059), top: B:163:0x0021, inners: #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:53:0x018b  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x01a5 A[Catch: Exception -> 0x0052, TryCatch #7 {Exception -> 0x0052, blocks: (B:3:0x0021, B:6:0x004c, B:13:0x0076, B:16:0x00a4, B:19:0x00c0, B:23:0x00d5, B:25:0x00e1, B:39:0x0113, B:40:0x011a, B:46:0x0143, B:47:0x0162, B:44:0x0125, B:48:0x0167, B:50:0x0179, B:52:0x017f, B:54:0x018c, B:56:0x0192, B:58:0x019d, B:60:0x01b6, B:62:0x01cd, B:64:0x01d7, B:65:0x01db, B:59:0x01a5, B:12:0x0071, B:11:0x0059), top: B:163:0x0021, inners: #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:62:0x01cd A[Catch: Exception -> 0x0052, TryCatch #7 {Exception -> 0x0052, blocks: (B:3:0x0021, B:6:0x004c, B:13:0x0076, B:16:0x00a4, B:19:0x00c0, B:23:0x00d5, B:25:0x00e1, B:39:0x0113, B:40:0x011a, B:46:0x0143, B:47:0x0162, B:44:0x0125, B:48:0x0167, B:50:0x0179, B:52:0x017f, B:54:0x018c, B:56:0x0192, B:58:0x019d, B:60:0x01b6, B:62:0x01cd, B:64:0x01d7, B:65:0x01db, B:59:0x01a5, B:12:0x0071, B:11:0x0059), top: B:163:0x0021, inners: #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:69:0x026c  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x0299 A[Catch: Exception -> 0x02d8, TryCatch #3 {Exception -> 0x02d8, blocks: (B:67:0x0227, B:70:0x026d, B:78:0x0299, B:81:0x02ac, B:110:0x032e, B:114:0x033e, B:116:0x034a, B:121:0x035b, B:123:0x0371, B:125:0x0380, B:128:0x0388, B:130:0x0391, B:132:0x03a2, B:134:0x03cb, B:135:0x03ce, B:137:0x03e4, B:140:0x03f3, B:131:0x039a, B:84:0x02b6, B:85:0x02bb, B:87:0x02cd, B:97:0x02ff, B:99:0x0305, B:101:0x0311, B:102:0x0315, B:104:0x031b, B:96:0x02f9, B:95:0x02e2, B:73:0x0274, B:76:0x0285), top: B:155:0x0227, inners: #0, #6 }] */
    /* JADX WARN: Removed duplicated region for block: B:99:0x0305 A[Catch: Exception -> 0x02d8, TryCatch #3 {Exception -> 0x02d8, blocks: (B:67:0x0227, B:70:0x026d, B:78:0x0299, B:81:0x02ac, B:110:0x032e, B:114:0x033e, B:116:0x034a, B:121:0x035b, B:123:0x0371, B:125:0x0380, B:128:0x0388, B:130:0x0391, B:132:0x03a2, B:134:0x03cb, B:135:0x03ce, B:137:0x03e4, B:140:0x03f3, B:131:0x039a, B:84:0x02b6, B:85:0x02bb, B:87:0x02cd, B:97:0x02ff, B:99:0x0305, B:101:0x0311, B:102:0x0315, B:104:0x031b, B:96:0x02f9, B:95:0x02e2, B:73:0x0274, B:76:0x0285), top: B:155:0x0227, inners: #0, #6 }] */
    /* JADX WARN: Type inference failed for: r5v11 */
    /* JADX WARN: Type inference failed for: r5v12, types: [org.json.JSONObject] */
    /* JADX WARN: Type inference failed for: r5v14 */
    /* JADX WARN: Type inference failed for: r5v15 */
    /* JADX WARN: Type inference failed for: r5v33 */
    /* JADX WARN: Type inference failed for: r5v34 */
    /* JADX WARN: Type inference failed for: r5v8, types: [boolean] */
    /* JADX WARN: Type inference failed for: r5v9 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void g(android.content.Context r28, java.lang.String r29) {
        /*
            Method dump skipped, instructions count: 1088
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.c.g(android.content.Context, java.lang.String):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x00a4 A[Catch: Exception -> 0x0078, TryCatch #2 {Exception -> 0x0078, blocks: (B:5:0x0057, B:7:0x0070, B:16:0x00a4, B:17:0x00b0, B:19:0x00c5, B:21:0x00cf, B:22:0x00d3, B:25:0x00df, B:27:0x01fe, B:31:0x0210, B:14:0x009d, B:12:0x007e), top: B:45:0x0057, inners: #3 }] */
    /* JADX WARN: Removed duplicated region for block: B:19:0x00c5 A[Catch: Exception -> 0x0078, TryCatch #2 {Exception -> 0x0078, blocks: (B:5:0x0057, B:7:0x0070, B:16:0x00a4, B:17:0x00b0, B:19:0x00c5, B:21:0x00cf, B:22:0x00d3, B:25:0x00df, B:27:0x01fe, B:31:0x0210, B:14:0x009d, B:12:0x007e), top: B:45:0x0057, inners: #3 }] */
    /* JADX WARN: Removed duplicated region for block: B:24:0x00dd  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x01fe A[Catch: Exception -> 0x0078, TryCatch #2 {Exception -> 0x0078, blocks: (B:5:0x0057, B:7:0x0070, B:16:0x00a4, B:17:0x00b0, B:19:0x00c5, B:21:0x00cf, B:22:0x00d3, B:25:0x00df, B:27:0x01fe, B:31:0x0210, B:14:0x009d, B:12:0x007e), top: B:45:0x0057, inners: #3 }] */
    /* JADX WARN: Removed duplicated region for block: B:28:0x020b  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x020f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void h(android.content.Context r24, boolean r25) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 675
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.c.h(android.content.Context, boolean):void");
    }

    public final void k(com.onetrust.otpublishers.headless.Internal.Preferences.e eVar, JSONArray jSONArray) throws JSONException {
        OTPublishersHeadlessSDK oTPublishersHeadlessSDK = new OTPublishersHeadlessSDK(this.a);
        JSONObject jSONObject = new JSONObject();
        for (int i = 0; i < jSONArray.length(); i++) {
            try {
                JSONObject jSONObject2 = jSONArray.getJSONObject(i);
                jSONObject.put(jSONObject2.getString("CustomGroupId"), c(oTPublishersHeadlessSDK, jSONObject2, jSONObject));
            } catch (JSONException e) {
                Z.p("Error on parsing vendor count for categories : ", e, "IAB2V2Flow", 6);
            }
        }
        JSONObject vendorListUI = oTPublishersHeadlessSDK.getVendorListUI(OTVendorListMode.IAB);
        if (vendorListUI != null) {
            try {
                jSONObject.put("activeIabVendorsCount", String.valueOf(vendorListUI.length()));
            } catch (JSONException e2) {
                Z.p("Error on setting active vendors count : ", e2, "IAB2V2Flow", 6);
            }
        }
        OTLogger.c("IAB2V2Flow", 3, "Setting vendorCountForCategoryString = " + jSONObject);
        L.i(jSONObject, eVar.a.b().edit(), "OT_VENDOR_COUNT_FOR_CATEGORIES");
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void s() throws JSONException {
        Object[] objArr;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        boolean z;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar2;
        String string;
        String[] strArrSplit = new String[0];
        Context context = this.a;
        String string2 = PreferenceManager.getDefaultSharedPreferences(context).getString(OTIABTCFKeys.IABTCF_ADD_TL_CONSENT, "");
        if (string2 != null && !com.onetrust.otpublishers.headless.Internal.a.j(string2)) {
            strArrSplit = string2.substring(string2.lastIndexOf("~") + 1).split("\\.");
        }
        String[] strArr = strArrSplit;
        if (strArr.length > 0) {
            SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
            if (Q.a(context)) {
                fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
                objArr = true;
            } else {
                objArr = false;
                fVar = null;
            }
            if (objArr != false) {
                sharedPreferences = fVar;
            }
            try {
                string = sharedPreferences.getString("OT_GOOGLE_ACTIVE_VENDOR_LIST", null);
            } catch (JSONException e) {
                Z.p("error while getting culture data json on getActiveGoogleVendors, err: ", e, "OneTrust", 6);
            }
            JSONObject jSONObject = !com.onetrust.otpublishers.headless.Internal.a.j(string) ? new JSONObject(string) : null;
            if (jSONObject != null) {
                for (int i = 0; i < jSONObject.length(); i++) {
                    try {
                        String string3 = jSONObject.names().get(i).toString();
                        JSONObject jSONObject2 = jSONObject.getJSONObject(string3);
                        if (jSONObject2.length() > 0 && jSONObject2.getInt(OTVendorUtils.CONSENT_TYPE) != -1) {
                            jSONObject2.put(OTVendorUtils.CONSENT_TYPE, Arrays.asList(strArr).contains(string3) ? 1 : 0);
                            jSONObject.put(string3, jSONObject2);
                            SharedPreferences sharedPreferences2 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                            if (AbstractC3605e0.a(context.getSharedPreferences("com.onetrust.otpublishers.headless.preference".concat("OTT_DEFAULT_USER"), 0).getString("OT_ENABLE_MULTI_PROFILE", Boolean.FALSE.toString()))) {
                                fVar2 = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences2, sharedPreferences2.getString("OT_ACTIVE_PROFILE_ID", ""));
                                z = true;
                            } else {
                                z = false;
                                fVar2 = null;
                            }
                            if (z) {
                                sharedPreferences2 = fVar2;
                            }
                            sharedPreferences2.edit().putString("OT_GOOGLE_ACTIVE_VENDOR_LIST", jSONObject.toString()).apply();
                        }
                    } catch (JSONException e2) {
                        Z.p("Saved active google vendor list not found.", e2, "IABHelper", 3);
                        return;
                    }
                }
            }
        }
    }

    public final String t(String str) {
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
        try {
            JSONObject jSONObject = new JSONObject(sharedPreferences.getString("OT_IAB_PURPOSE_TYPES", ""));
            if (jSONObject.has(str)) {
                OTLogger.c("IABHelper", 3, "IAB type of " + str + ": " + jSONObject.getString(str));
                return jSONObject.getString(str);
            }
        } catch (JSONException e) {
            Z.p("Error while getting IAB type of updated group : ", e, "IABHelper", 6);
        }
        return "";
    }

    public final boolean x(String str) {
        boolean z = false;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(t(str)) && (t(str).equals("purposes") || t(str).equals("special_feature_opt_ins"))) {
            z = true;
        }
        OTLogger.c("IABHelper", 3, "IAB group " + str + " : " + z);
        return z;
    }
}
