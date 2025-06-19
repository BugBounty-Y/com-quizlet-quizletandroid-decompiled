package com.onetrust.otpublishers.headless.Internal.Helper;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3605e0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.P;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Q;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.Keys.OTGppKeys;
import com.onetrust.otpublishers.headless.Public.uiutils.OTVendorUtils;
import java.util.Iterator;
import java.util.Locale;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class s {
    public final Context a;
    public JSONObject b = new JSONObject();
    public JSONObject c = new JSONObject();
    public final SharedPreferences d;
    public final com.onetrust.otpublishers.headless.Internal.Preferences.e e;
    public String f;
    public final g g;

    public s(@NonNull Context context) {
        this.a = context;
        this.d = new com.onetrust.otpublishers.headless.Internal.Preferences.d(context).b();
        this.e = new com.onetrust.otpublishers.headless.Internal.Preferences.e(context);
        this.g = new g(context);
    }

    public static void c(c cVar, JSONObject jSONObject, JSONObject jSONObject2) throws JSONException {
        for (int i = 0; i < jSONObject2.length(); i++) {
            String string = jSONObject2.names().getString(i);
            if (cVar.x(string)) {
                jSONObject.getJSONObject(cVar.t(string)).put(c.q(string), jSONObject2.getInt(string));
            }
        }
        OTLogger.c("CustomGroupDetails", 3, "IAB purposes updated : " + jSONObject);
    }

    public final int a(String str) {
        try {
            return this.b.has(str) ? this.b.getInt(str) : this.e.a(str);
        } catch (JSONException e) {
            Z.p("Error while getting updated value of Purpose Consent ", e, "CustomGroupDetails", 6);
            return -1;
        }
    }

    public final void b() {
        Context context = this.a;
        new com.onetrust.otpublishers.headless.gpp.templates.d(context).a();
        new com.onetrust.otpublishers.headless.gpp.templates.a(context).a();
        new com.onetrust.otpublishers.headless.gpp.templates.f(context).b();
        new com.onetrust.otpublishers.headless.gpp.templates.b(context).a();
        new com.onetrust.otpublishers.headless.gpp.templates.c(context).a();
        new com.onetrust.otpublishers.headless.gpp.templates.e(context).a();
        new com.onetrust.otpublishers.headless.gpp.c(context).c();
    }

    /* JADX WARN: Removed duplicated region for block: B:47:0x0109 A[Catch: JSONException -> 0x0111, TRY_ENTER, TRY_LEAVE, TryCatch #0 {JSONException -> 0x0111, blocks: (B:47:0x0109, B:53:0x0118, B:55:0x011e, B:57:0x0124, B:59:0x013b, B:60:0x0142, B:62:0x0148, B:65:0x015e, B:66:0x0163, B:67:0x0167, B:68:0x016a, B:69:0x016e), top: B:73:0x0107 }] */
    /* JADX WARN: Removed duplicated region for block: B:51:0x0114  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void d(java.lang.String r17, org.json.JSONObject r18, boolean r19) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 410
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.s.d(java.lang.String, org.json.JSONObject, boolean):void");
    }

    public final void e(String str, boolean z) {
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        boolean z2;
        new JSONObject();
        Context context = this.a;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Q.a(context)) {
            fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z2 = true;
        } else {
            fVar = null;
            z2 = false;
        }
        if (z2) {
            sharedPreferences = fVar;
        }
        new com.onetrust.otpublishers.headless.Internal.Preferences.d(context);
        String string = sharedPreferences.getString("OTT_INTERNAL_SDK_GROUP_MAP", "");
        JSONArray jSONArray = new JSONArray();
        if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            try {
                JSONObject jSONObject = new JSONObject(string);
                if (jSONObject.has(str)) {
                    jSONArray = new JSONArray(jSONObject.get(str).toString());
                }
            } catch (JSONException e) {
                Z.p("Error while fetching Sdks by group : ", e, "SdkListHelper", 6);
            }
        }
        OTLogger.c("CustomGroupDetails", 4, "SDK Ids of  : " + str + " is " + jSONArray);
        for (int i = 0; i < jSONArray.length(); i++) {
            try {
                this.g.h(jSONArray.get(i).toString(), z);
            } catch (JSONException e2) {
                Z.p("Error in setting group sdk status ", e2, "OneTrust", 6);
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:118:0x02b3  */
    /* JADX WARN: Removed duplicated region for block: B:119:0x02be  */
    /* JADX WARN: Removed duplicated region for block: B:121:0x02c2  */
    /* JADX WARN: Removed duplicated region for block: B:124:0x02e3  */
    /* JADX WARN: Removed duplicated region for block: B:128:0x0304  */
    /* JADX WARN: Removed duplicated region for block: B:129:0x0306 A[Catch: JSONException -> 0x0334, TryCatch #8 {JSONException -> 0x0334, blocks: (B:126:0x02f4, B:145:0x033d, B:129:0x0306, B:131:0x030c, B:133:0x0312, B:136:0x031d, B:138:0x0323, B:140:0x032d, B:144:0x0338), top: B:224:0x02f4 }] */
    /* JADX WARN: Removed duplicated region for block: B:150:0x035c  */
    /* JADX WARN: Removed duplicated region for block: B:154:0x038a A[Catch: Exception -> 0x0390, TRY_LEAVE, TryCatch #0 {Exception -> 0x0390, blocks: (B:152:0x0380, B:154:0x038a), top: B:209:0x0380 }] */
    /* JADX WARN: Removed duplicated region for block: B:158:0x0399  */
    /* JADX WARN: Removed duplicated region for block: B:161:0x03ab  */
    /* JADX WARN: Removed duplicated region for block: B:163:0x03d3  */
    /* JADX WARN: Removed duplicated region for block: B:168:0x03e7 A[Catch: JSONException -> 0x03f6, TryCatch #10 {JSONException -> 0x03f6, blocks: (B:166:0x03da, B:168:0x03e7, B:170:0x03ed, B:174:0x03f9, B:176:0x03ff), top: B:228:0x03da }] */
    /* JADX WARN: Removed duplicated region for block: B:178:0x0405  */
    /* JADX WARN: Removed duplicated region for block: B:184:0x0424 A[Catch: Exception -> 0x042c, TRY_LEAVE, TryCatch #2 {Exception -> 0x042c, blocks: (B:182:0x0419, B:184:0x0424), top: B:213:0x0419 }] */
    /* JADX WARN: Removed duplicated region for block: B:190:0x0444  */
    /* JADX WARN: Removed duplicated region for block: B:191:0x044f  */
    /* JADX WARN: Removed duplicated region for block: B:193:0x0453  */
    /* JADX WARN: Removed duplicated region for block: B:196:0x045d  */
    /* JADX WARN: Removed duplicated region for block: B:247:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:57:0x014a  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x0161  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x01a7 A[Catch: Exception -> 0x01ad, TRY_ENTER, TryCatch #1 {Exception -> 0x01ad, blocks: (B:73:0x01a7, B:78:0x01b7, B:77:0x01b1), top: B:211:0x01a5 }] */
    /* JADX WARN: Removed duplicated region for block: B:76:0x01af  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x01c4  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x020f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void f(boolean r28, boolean r29) {
        /*
            Method dump skipped, instructions count: 1188
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.s.f(boolean, boolean):void");
    }

    public final void g(boolean z, boolean z2, JSONObject jSONObject, boolean z3) throws Throwable {
        boolean z4;
        boolean z5;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar2;
        boolean z6;
        String str;
        boolean z7;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar3;
        boolean z8;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar4;
        String str2;
        int length = jSONObject.length();
        Context context = this.a;
        if (length > 0) {
            JSONArray jSONArrayNames = jSONObject.getJSONObject("purposes").names();
            JSONArray jSONArrayNames2 = jSONObject.getJSONObject("special_feature_opt_ins").names();
            JSONArray jSONArrayNames3 = jSONObject.getJSONObject("stacks").names();
            String str3 = "purposeLegitimateInterests";
            JSONArray jSONArrayNames4 = jSONObject.getJSONObject("purposeLegitimateInterests").names();
            SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
            SharedPreferences sharedPreferencesA = Y.a(context);
            Boolean bool = Boolean.FALSE;
            if (Z.r(bool, sharedPreferencesA, "OT_ENABLE_MULTI_PROFILE")) {
                str = "stacks";
                fVar3 = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
                z7 = true;
            } else {
                str = "stacks";
                z7 = false;
                fVar3 = null;
            }
            if (z7) {
                sharedPreferences = fVar3;
            }
            String string = sharedPreferences.getString("OT_IAB_ACTIVE_VENDORLIST", "");
            OTLogger.c("IABHelper", 3, !com.onetrust.otpublishers.headless.Internal.a.j(string) ? AbstractC0147y.d("Saved IAB Active Vendor List : ", string) : "Vendor List is empty");
            JSONObject jSONObject2 = com.onetrust.otpublishers.headless.Internal.a.j(string) ? new JSONObject() : new JSONObject(string);
            if (!z2) {
                SharedPreferences sharedPreferences2 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                if (Z.r(bool, Y.a(context), "OT_ENABLE_MULTI_PROFILE")) {
                    fVar4 = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences2, sharedPreferences2.getString("OT_ACTIVE_PROFILE_ID", ""));
                    z8 = true;
                } else {
                    z8 = false;
                    fVar4 = null;
                }
                if (z8) {
                    sharedPreferences2 = fVar4;
                }
                if (sharedPreferences2.getBoolean("IS_IAB2_TEMPLATE", false)) {
                    if (jSONArrayNames != null && jSONArrayNames.length() > 0) {
                        for (int i = 0; i < jSONArrayNames.length(); i++) {
                            jSONObject.getJSONObject("purposes").put(jSONArrayNames.getString(i), z ? 1 : 0);
                        }
                    }
                    if (jSONArrayNames2 != null && jSONArrayNames2.length() > 0) {
                        for (int i2 = 0; i2 < jSONArrayNames2.length(); i2++) {
                            jSONObject.getJSONObject("special_feature_opt_ins").put(jSONArrayNames2.getString(i2), z ? 1 : 0);
                        }
                    }
                    if (jSONArrayNames3 != null && jSONArrayNames3.length() > 0) {
                        for (int i3 = 0; i3 < jSONArrayNames3.length(); i3++) {
                            jSONObject.getJSONObject(str).put(jSONArrayNames3.getString(i3), z ? 1 : 0);
                        }
                    }
                    OTLogger.c("RejectAllFlow", 3, "Is interaction type reject all = " + (!z) + " , reject all type isRejectObjectToLI = " + z3);
                    for (int i4 = 0; i4 < jSONObject2.length(); i4++) {
                        JSONArray jSONArrayNames5 = jSONObject2.names();
                        if (jSONArrayNames5 != null) {
                            if (jSONObject2.getJSONObject(jSONArrayNames5.get(i4).toString()).getInt(OTVendorUtils.CONSENT_TYPE) >= 0) {
                                jSONObject2.getJSONObject(jSONArrayNames5.get(i4).toString()).put(OTVendorUtils.CONSENT_TYPE, z ? 1 : 0);
                            }
                            if (jSONObject2.getJSONObject(jSONArrayNames5.get(i4).toString()).getInt(OTVendorUtils.LEGITIMATE_CONSENT_TYPE) >= 0 && (z || z3)) {
                                jSONObject2.getJSONObject(jSONArrayNames5.get(i4).toString()).put(OTVendorUtils.LEGITIMATE_CONSENT_TYPE, z ? 1 : 0);
                            }
                        }
                    }
                    if ((z || z3) && jSONArrayNames4 != null && jSONArrayNames4.length() > 0) {
                        int i5 = 0;
                        while (i5 < jSONArrayNames4.length()) {
                            JSONArray jSONArray = jSONArrayNames4;
                            if ("1".equals(jSONArray.getString(i5))) {
                                str2 = str3;
                            } else {
                                str2 = str3;
                                jSONObject.getJSONObject(str2).put(jSONArray.getString(i5), z ? 1 : 0);
                            }
                            i5++;
                            jSONArrayNames4 = jSONArray;
                            str3 = str2;
                        }
                    }
                }
            }
            z4 = true;
            d(jSONObject.toString(), jSONObject2, true);
        } else {
            z4 = true;
        }
        SharedPreferences sharedPreferences3 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        SharedPreferences sharedPreferencesA2 = Y.a(context);
        Boolean bool2 = Boolean.FALSE;
        if (Z.r(bool2, sharedPreferencesA2, "OT_ENABLE_MULTI_PROFILE")) {
            fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences3, sharedPreferences3.getString("OT_ACTIVE_PROFILE_ID", ""));
            z5 = z4;
        } else {
            z5 = false;
            fVar = null;
        }
        if (z5) {
            sharedPreferences3 = fVar;
        }
        if (sharedPreferences3.getBoolean("IS_IAB2_TEMPLATE", false)) {
            return;
        }
        SharedPreferences sharedPreferences4 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Z.r(bool2, Y.a(context), "OT_ENABLE_MULTI_PROFILE")) {
            fVar2 = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences4, sharedPreferences4.getString("OT_ACTIVE_PROFILE_ID", ""));
            z6 = z4;
        } else {
            fVar2 = null;
            z6 = false;
        }
        new com.onetrust.otpublishers.headless.gpp.b(context);
        if (z6) {
            sharedPreferences4 = fVar2;
        }
        new com.onetrust.otpublishers.headless.Internal.Preferences.a(context).a(0, sharedPreferences4.getBoolean("OT_GPP_IS_ENABLED", false) ? OTGppKeys.IAB_GPP_GDPRAPPLIES : "IABTCF_gdprApplies");
        OTLogger.c("CustomGroupDetails", 4, "Setting gdprApplies value to 0.");
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x004a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean h(java.lang.String r12, org.json.JSONObject r13, org.json.JSONObject r14) throws org.json.JSONException {
        /*
            r11 = this;
            com.onetrust.otpublishers.headless.Internal.Helper.p r0 = new com.onetrust.otpublishers.headless.Internal.Helper.p
            android.content.Context r1 = r11.a
            r0.<init>(r1)
            java.lang.String r1 = r0.c()
            boolean r2 = com.onetrust.otpublishers.headless.Internal.a.j(r12)
            if (r2 == 0) goto L17
            org.json.JSONObject r12 = new org.json.JSONObject
            r12.<init>()
            goto L1d
        L17:
            org.json.JSONObject r2 = new org.json.JSONObject
            r2.<init>(r12)
            r12 = r2
        L1d:
            java.util.Iterator r2 = r13.keys()
            r3 = 0
            r4 = r3
        L23:
            boolean r5 = r2.hasNext()
            java.lang.String r6 = "FIRST_TIME_CONSENT_LOG"
            android.content.SharedPreferences r7 = r11.d
            if (r5 == 0) goto L5f
            java.lang.Object r5 = r2.next()
            java.lang.String r5 = (java.lang.String) r5
            int r8 = r13.getInt(r5)
            boolean r9 = r12.has(r5)
            r10 = 1
            if (r9 == 0) goto L4a
            int r9 = r12.getInt(r5)
            boolean r6 = r7.getBoolean(r6, r10)
            if (r6 != 0) goto L4a
            if (r9 == r8) goto L51
        L4a:
            r12.put(r5, r8)
            r14.put(r5, r8)
            r4 = r10
        L51:
            boolean r5 = r5.equals(r1)
            if (r5 == 0) goto L23
            if (r8 != r10) goto L5a
            goto L5b
        L5a:
            r10 = r3
        L5b:
            r0.b(r10, r3)
            goto L23
        L5f:
            java.lang.StringBuilder r13 = new java.lang.StringBuilder
            java.lang.String r14 = "consent values saved as  "
            r13.<init>(r14)
            r13.append(r12)
            java.lang.String r13 = r13.toString()
            java.lang.String r14 = "CustomGroupDetails"
            r0 = 4
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r14, r0, r13)
            android.content.SharedPreferences$Editor r13 = r7.edit()
            android.content.SharedPreferences$Editor r13 = r13.putBoolean(r6, r3)
            r13.apply()
            android.content.SharedPreferences$Editor r13 = r7.edit()
            java.lang.String r14 = "OTT_CONSENT_STATUS"
            com.google.android.gms.internal.mlkit_vision_document_scanner.L.i(r12, r13, r14)
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.s.h(java.lang.String, org.json.JSONObject, org.json.JSONObject):boolean");
    }

    public final boolean i(boolean z, boolean z2, JSONArray jSONArray, JSONObject jSONObject) throws JSONException {
        JSONObject jSONObject2 = new JSONObject();
        if (jSONObject.has("purposes")) {
            jSONObject2 = jSONObject.getJSONObject("purposes");
        }
        JSONObject jSONObject3 = new JSONObject();
        if (jSONObject.has("special_feature_opt_ins")) {
            jSONObject3 = jSONObject.getJSONObject("special_feature_opt_ins");
        }
        if (jSONArray == null || jSONArray.length() <= 0) {
            OTLogger.c("CustomGroupDetails", 6, "No categories found to update");
            return false;
        }
        int i = 0;
        while (true) {
            boolean z3 = true;
            if (i >= jSONArray.length()) {
                return true;
            }
            String string = jSONArray.getString(i);
            if ((!string.startsWith("IAB") && !string.startsWith("ISF")) || jSONObject2.has(c.q(string)) || (string.startsWith("ISF") && jSONObject3.has(c.q(string)))) {
                if (!z2) {
                    z3 = z;
                } else if (this.e.a(string) != 1) {
                    z3 = false;
                }
                n(string, z3);
            }
            i++;
        }
    }

    public final int j(String str) throws JSONException {
        boolean z;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        boolean z2;
        JSONObject jSONObject;
        Context context = this.a;
        int i = -1;
        try {
            if (this.c.has(str)) {
                return this.c.getInt(str);
            }
            boolean zA = false;
            SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
            com.onetrust.otpublishers.headless.Internal.Preferences.f fVar2 = null;
            if (AbstractC3605e0.a(new com.onetrust.otpublishers.headless.Internal.Preferences.d(context, "OTT_DEFAULT_USER").b().getString("OT_ENABLE_MULTI_PROFILE", Boolean.FALSE.toString()))) {
                fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
                z = true;
            } else {
                z = false;
                fVar = null;
            }
            SharedPreferences sharedPreferences2 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
            if (new com.onetrust.otpublishers.headless.Internal.profile.c(context).t()) {
                fVar2 = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences2, sharedPreferences2.getString("OT_ACTIVE_PROFILE_ID", ""));
                z2 = true;
            } else {
                z2 = false;
            }
            if (z2) {
                sharedPreferences2 = fVar2;
            }
            String string = sharedPreferences2.getString("OTT_CULTURE_DOMAIN_DATA", "");
            if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                jSONObject = new JSONObject();
            } else {
                try {
                    jSONObject = new JSONObject(string);
                } catch (JSONException e) {
                    OTLogger.c("OneTrust", 6, "error while returning culture domain data, err: " + e.getMessage());
                }
            }
            String strQ = c.q(str);
            if (z) {
                sharedPreferences = fVar;
            }
            String string2 = sharedPreferences.getString("OTT_IAB_CONSENTABLE_PURPOSES", "");
            try {
                zA = new com.onetrust.otpublishers.headless.Internal.Models.b(context).a(jSONObject);
            } catch (JSONException e2) {
                OTLogger.c("IABHelper", 3, "error on checking reconsent for IAB status, " + e2);
            }
            try {
                if (!com.onetrust.otpublishers.headless.Internal.a.j(string2)) {
                    JSONObject jSONObject2 = new JSONObject(string2);
                    if (!jSONObject2.getJSONObject("purposeLegitimateInterests").has(strQ)) {
                        return -1;
                    }
                    if (!zA) {
                        i = jSONObject2.getJSONObject("purposeLegitimateInterests").getInt(strQ);
                        return i;
                    }
                }
            } catch (JSONException e3) {
                OTLogger.c("IABHelper", 3, "unable to get iab consent status" + e3);
            }
            return 1;
        } catch (JSONException e4) {
            Z.p("Error while getting updated value of Purpose Legit Interest ", e4, "CustomGroupDetails", 6);
            return i;
        }
    }

    public final String k() throws JSONException {
        String strJ;
        JSONObject jSONObject;
        com.onetrust.otpublishers.headless.Internal.Preferences.e eVar = this.e;
        String string = eVar.a.b().getString("OTT_PARENT_CHILD_GROUPS", "");
        String string2 = this.d.getString("OTT_CONSENT_STATUS", "");
        String string3 = eVar.a.b().getString("OTT_IAB_CONSENTABLE_PURPOSES", "");
        JSONObject jSONObject2 = new JSONObject();
        JSONObject jSONObject3 = new JSONObject();
        if (!com.onetrust.otpublishers.headless.Internal.a.j(string3)) {
            JSONObject jSONObject4 = new JSONObject(string3);
            if (jSONObject4.has("purposes")) {
                jSONObject2 = jSONObject4.getJSONObject("purposes");
            }
            if (jSONObject4.has("special_feature_opt_ins")) {
                jSONObject3 = jSONObject4.getJSONObject("special_feature_opt_ins");
            }
        }
        JSONObject jSONObject5 = new JSONObject();
        if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            jSONObject5 = new JSONObject(string);
        }
        JSONObject jSONObject6 = new JSONObject();
        Iterator<String> itKeys = jSONObject5.keys();
        while (itKeys.hasNext()) {
            String next = itKeys.next();
            JSONArray jSONArray = jSONObject5.getJSONArray(next);
            JSONArray jSONArray2 = new JSONArray();
            for (int i = 0; i < jSONArray.length(); i++) {
                String string4 = jSONArray.getString(i);
                if (string2 == null || com.onetrust.otpublishers.headless.Internal.a.j(string2)) {
                    strJ = "customGroup Value not set.";
                } else {
                    Locale locale = Locale.ENGLISH;
                    String lowerCase = string4.toLowerCase(locale);
                    try {
                        jSONObject = new JSONObject(string2.toLowerCase(locale));
                    } catch (JSONException unused) {
                        jSONObject = null;
                    }
                    try {
                        if (jSONObject.has(lowerCase) && ((!string4.startsWith("IAB") && !string4.startsWith("ISF")) || jSONObject2.has(c.q(string4)) || (string4.startsWith("ISF") && jSONObject3.has(c.q(string4))))) {
                            jSONArray2.put(string4);
                        }
                    } catch (JSONException unused2) {
                        strJ = assistantMode.refactored.a.j("error in json parsing for customGroup Value = ", jSONObject);
                        OTLogger.c("OTSPUtils", 4, strJ);
                    }
                }
                OTLogger.c("OTSPUtils", 4, strJ);
            }
            jSONObject6.put(next, jSONArray2);
        }
        return jSONObject6.toString();
    }

    public final void l(boolean z, boolean z2) {
        boolean z3;
        g gVar;
        SharedPreferences sharedPreferences = this.d;
        String string = sharedPreferences.getString("OTT_IAB_CONSENTABLE_PURPOSES", "");
        sharedPreferences.getString("OTT_ALWAYS_ACTIVE_GROUPS", "");
        String string2 = sharedPreferences.getString("OT_INTERNAL_SDK_STATUS_MAP", "");
        boolean zContains = sharedPreferences.contains("OT_GROUP_ID_OBJECT");
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar = null;
        com.onetrust.otpublishers.headless.Internal.Preferences.e eVar = this.e;
        if (!zContains) {
            eVar.getClass();
            JSONArray jSONArray = new JSONArray();
            String string3 = eVar.a.b().getString("OTT_PC_DATA", null);
            if (!com.onetrust.otpublishers.headless.Internal.a.j(string3)) {
                try {
                    jSONArray = new JSONObject(string3).getJSONArray("Groups");
                } catch (JSONException e) {
                    Z.p("Error on getting pc group array, message = ", e, "OTSPUtils", 6);
                }
            }
            P.i(jSONArray, sharedPreferences);
        }
        String string4 = sharedPreferences.getString("OT_GROUP_ID_OBJECT", "");
        try {
            JSONObject jSONObject = new JSONObject();
            if (!com.onetrust.otpublishers.headless.Internal.a.j(string4)) {
                jSONObject = new JSONObject(string4);
            }
            JSONObject jSONObject2 = new JSONObject();
            if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                jSONObject2 = new JSONObject(string);
            }
            boolean zI = i(z, z2, jSONObject.names(), jSONObject2);
            if (eVar.a.b().getBoolean("OT_GOOGLE_VENDORS_ENABLED_STATE", false) && !z2) {
                a.c(sharedPreferences, eVar, z);
            }
            t.a(z, z2, eVar);
            Context context = this.a;
            SharedPreferences sharedPreferences2 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
            if (new com.onetrust.otpublishers.headless.Internal.profile.c(context).t()) {
                fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences2, sharedPreferences2.getString("OT_ACTIVE_PROFILE_ID", ""));
                z3 = true;
            } else {
                z3 = false;
            }
            if (z3) {
                sharedPreferences2 = fVar;
            }
            g(z, z2, jSONObject2, !"LIActiveIfLegalBasis".equalsIgnoreCase(sharedPreferences2.getString("OT_SDK_REJECT_ALL_TYPE", "ObjectToLI")));
            if (zI && !com.onetrust.otpublishers.headless.Internal.a.j(string2) && string2 != null) {
                JSONObject jSONObject3 = new JSONObject(string2);
                Iterator<String> itKeys = jSONObject3.keys();
                boolean z4 = false;
                while (true) {
                    boolean zHasNext = itKeys.hasNext();
                    gVar = this.g;
                    if (!zHasNext) {
                        break;
                    }
                    String next = itKeys.next();
                    if (jSONObject3.getInt(next) == 1) {
                        z4 = true;
                    } else if (jSONObject3.getInt(next) == 0) {
                        z4 = false;
                    }
                    if (z2) {
                        gVar.h(next, z4);
                    } else {
                        gVar.h(next, z);
                    }
                }
                gVar.g(string2);
            }
            f(z2, true);
        } catch (JSONException e2) {
            Z.p("error while fetching all categories", e2, "CustomGroupDetails", 6);
        }
    }

    public final boolean m(String str, boolean z) {
        try {
            if (this.e.g(str)) {
                OTLogger.c("CustomGroupDetails", 4, "Consent not updated for Always Active group : " + str);
                return false;
            }
            this.b.put(str, z ? 1 : 0);
            OTLogger.c("CustomGroupDetails", 3, "Consent updated for group : " + str + " with value : " + z);
            return true;
        } catch (JSONException e) {
            Z.p("error in updating consent status. err = ", e, "CustomGroupDetails", 6);
            return false;
        }
    }

    public final boolean n(String str, boolean z) {
        boolean z2;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        String strJ;
        Context context = this.a;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        JSONObject jSONObject = null;
        if (Q.a(context)) {
            fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z2 = true;
        } else {
            z2 = false;
            fVar = null;
        }
        if (z2) {
            sharedPreferences = fVar;
        }
        String string = sharedPreferences.getString("OTT_CONSENT_STATUS", "");
        if (string != null && !com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            Locale locale = Locale.ENGLISH;
            String lowerCase = str.toLowerCase(locale);
            try {
                JSONObject jSONObject2 = new JSONObject(string.toLowerCase(locale));
                try {
                    if (jSONObject2.has(lowerCase)) {
                        boolean zM = m(str, z);
                        if (zM) {
                            e(str, z);
                        }
                        return zM;
                    }
                } catch (JSONException unused) {
                    jSONObject = jSONObject2;
                    strJ = assistantMode.refactored.a.j("error in json parsing for customGroup Value = ", jSONObject);
                    OTLogger.c("OTSPUtils", 4, strJ);
                    OTLogger.c("CustomGroupDetails", 4, "Group ID doesn't exist/not allowed to update status for " + str + " groupId.");
                    return false;
                }
            } catch (JSONException unused2) {
            }
            OTLogger.c("CustomGroupDetails", 4, "Group ID doesn't exist/not allowed to update status for " + str + " groupId.");
            return false;
        }
        strJ = "customGroup Value not set.";
        OTLogger.c("OTSPUtils", 4, strJ);
        OTLogger.c("CustomGroupDetails", 4, "Group ID doesn't exist/not allowed to update status for " + str + " groupId.");
        return false;
    }
}
