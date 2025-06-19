package com.onetrust.otpublishers.headless.Internal.Helper;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.annotation.NonNull;
import com.google.android.gms.internal.mlkit_vision_document_scanner.K;
import com.google.android.gms.internal.mlkit_vision_document_scanner.L;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import java.util.ArrayList;
import java.util.Iterator;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class g {
    public final SharedPreferences a;
    public final com.onetrust.otpublishers.headless.Internal.Preferences.e b;
    public final JSONObject c = new JSONObject();
    public final Context d;

    public g(@NonNull Context context) {
        this.d = context;
        this.a = new com.onetrust.otpublishers.headless.Internal.Preferences.d(context).b();
        this.b = new com.onetrust.otpublishers.headless.Internal.Preferences.e(context);
    }

    public final int a(String str, String str2, boolean z) {
        Integer numValueOf;
        boolean zJ = com.onetrust.otpublishers.headless.Internal.a.j(str2);
        com.onetrust.otpublishers.headless.Internal.Preferences.e eVar = this.b;
        if (zJ) {
            String strC = c(str);
            numValueOf = strC != null ? Integer.valueOf(eVar.a(strC)) : null;
            if (numValueOf != null) {
                return numValueOf.intValue();
            }
            return -1;
        }
        JSONObject jSONObject = new JSONObject(str2);
        if (str2.contains(str)) {
            if (jSONObject.getInt(str) == 2) {
                return z ? 2 : 1;
            }
            StringBuilder sbY = android.support.v4.media.session.a.y("SDK_ID ", str, "  Status ");
            sbY.append(jSONObject.get(str));
            OTLogger.c("SdkListHelper", 4, sbY.toString());
            return jSONObject.getInt(str);
        }
        String strC2 = c(str);
        numValueOf = strC2 != null ? Integer.valueOf(eVar.a(strC2)) : null;
        if (numValueOf != null) {
            return numValueOf.intValue();
        }
        K.c("Invalid SDK_ID passed - ", 4, str, "SdkListHelper");
        return -1;
    }

    public final int b(String str, boolean z) {
        String string = this.a.getString("OT_INTERNAL_SDK_STATUS_MAP", "");
        K.c("SDK Status Object - ", 4, string, "SdkListHelper");
        JSONObject jSONObject = this.c;
        if (jSONObject != null) {
            try {
                if (jSONObject.has(str)) {
                    return jSONObject.getInt(str);
                }
            } catch (JSONException e) {
                Z.p("Error while getting sdk status ", e, "SdkListHelper", 6);
                return -1;
            }
        }
        return a(str, string, z);
    }

    public final String c(String str) {
        String str2 = "";
        String string = this.a.getString("OTT_INTERNAL_SDK_GROUP_MAP", "");
        if (string.isEmpty()) {
            OTLogger.c("SdkListHelper", 3, "Empty sdkMap found");
            return null;
        }
        try {
            JSONObject jSONObject = new JSONObject(string);
            Iterator<String> itKeys = jSONObject.keys();
            while (itKeys.hasNext()) {
                String next = itKeys.next();
                if (jSONObject.get(next).toString().contains(str)) {
                    str2 = next;
                }
            }
            return str2;
        } catch (JSONException e) {
            Z.p("Error while fetching groupId by sdkId : ", e, "SdkListHelper", 6);
            return str2;
        }
    }

    public final void d(JSONObject jSONObject) {
        SharedPreferences sharedPreferences;
        int i;
        JSONArray jSONArray = new JSONArray();
        if (jSONObject.getJSONObject("culture").getJSONObject("DomainData").has("Groups")) {
            JSONArray jSONArray2 = jSONObject.getJSONObject("culture").getJSONObject("DomainData").getJSONArray("Groups");
            if (jSONArray2.length() > 0) {
                SharedPreferences sharedPreferences2 = this.a;
                String string = sharedPreferences2.getString("OTT_INTERNAL_SDK_GROUP_MAP", null);
                JSONObject jSONObject2 = !com.onetrust.otpublishers.headless.Internal.a.j(string) ? new JSONObject(string) : new JSONObject();
                String string2 = sharedPreferences2.getString("OT_INTERNAL_SDK_STATUS_MAP", "");
                JSONObject jSONObject3 = !com.onetrust.otpublishers.headless.Internal.a.j(string2) ? new JSONObject(string2) : new JSONObject();
                boolean zShouldShowBanner = new OTPublishersHeadlessSDK(this.d).shouldShowBanner();
                int i2 = 0;
                while (i2 < jSONArray2.length()) {
                    ArrayList arrayList = new ArrayList();
                    if ((!jSONArray2.getJSONObject(i2).has("ShowSDKListLink") || jSONArray2.getJSONObject(i2).getBoolean("ShowSDKListLink")) && jSONArray2.getJSONObject(i2).getJSONArray("FirstPartyCookies").length() > 0) {
                        int i3 = 0;
                        while (i3 < jSONArray2.getJSONObject(i2).getJSONArray("FirstPartyCookies").length()) {
                            String strOptString = jSONArray2.getJSONObject(i2).getJSONArray("FirstPartyCookies").getJSONObject(i3).optString("SdkId");
                            arrayList.add(strOptString);
                            SharedPreferences sharedPreferences3 = sharedPreferences2;
                            if (jSONArray2.getJSONObject(i2).optString("Status").contains("always")) {
                                i = 2;
                            } else {
                                int iB = !zShouldShowBanner ? b(strOptString, true) : -1;
                                i = (zShouldShowBanner || -1 == iB || 2 == iB) ? !jSONArray2.getJSONObject(i2).optString("Status").equals("inactive") ? 1 : 0 : iB;
                            }
                            jSONObject3.put(strOptString, i);
                            jSONObject2.put(jSONArray2.getJSONObject(i2).optString("CustomGroupId"), arrayList);
                            i3++;
                            sharedPreferences2 = sharedPreferences3;
                        }
                        sharedPreferences = sharedPreferences2;
                        OTLogger.c("SdkListHelper", 4, "Saving SDK Status map = " + jSONObject3);
                        sharedPreferences.edit().putString("OT_INTERNAL_SDK_STATUS_MAP", jSONObject3.toString()).apply();
                        jSONArray.put(jSONObject2);
                    } else {
                        sharedPreferences = sharedPreferences2;
                    }
                    i2++;
                    sharedPreferences2 = sharedPreferences;
                }
                L.i(jSONObject2, sharedPreferences2.edit(), "OTT_INTERNAL_SDK_GROUP_MAP");
            }
        }
    }

    public final void e(JSONObject jSONObject, JSONObject jSONObject2) throws JSONException {
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        o oVar;
        Iterator<String> itKeys = jSONObject.keys();
        while (itKeys.hasNext()) {
            String next = itKeys.next();
            int i = jSONObject.getInt(next);
            if (jSONObject2.has(next)) {
                int i2 = jSONObject2.getInt(next);
                Context context = this.d;
                boolean z = false;
                SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                if (Z.r(Boolean.FALSE, Y.a(context), "OT_ENABLE_MULTI_PROFILE")) {
                    fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
                    z = true;
                } else {
                    fVar = null;
                }
                if (z) {
                    sharedPreferences = fVar;
                }
                String string = sharedPreferences.getString("OTT_LAST_GIVEN_CONSENT", "0");
                if (0 == (com.onetrust.otpublishers.headless.Internal.a.j(string) ? 0L : Long.parseLong(string))) {
                    jSONObject2.put(next, i);
                    oVar = new o(context);
                } else if (i2 != i) {
                    jSONObject2.put(next, i);
                    oVar = new o(context);
                }
                oVar.a(i, next);
            }
        }
    }

    public final JSONArray f(String str) {
        String string = this.a.getString("OTT_INTERNAL_SDK_GROUP_MAP", "");
        JSONArray jSONArray = new JSONArray();
        if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            try {
                JSONObject jSONObject = new JSONObject(string);
                if (jSONObject.has(str)) {
                    return new JSONArray(jSONObject.get(str).toString());
                }
            } catch (JSONException e) {
                Z.p("Error while fetching Sdks by group : ", e, "SdkListHelper", 6);
            }
        }
        return jSONArray;
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x0019  */
    /* JADX WARN: Removed duplicated region for block: B:17:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void g(java.lang.String r5) {
        /*
            r4 = this;
            org.json.JSONObject r0 = new org.json.JSONObject     // Catch: org.json.JSONException -> Ld
            r0.<init>(r5)     // Catch: org.json.JSONException -> Ld
            org.json.JSONObject r5 = r4.c     // Catch: org.json.JSONException -> Lb
            r4.e(r5, r0)     // Catch: org.json.JSONException -> Lb
            goto L17
        Lb:
            r5 = move-exception
            goto Lf
        Ld:
            r5 = move-exception
            r0 = 0
        Lf:
            java.lang.String r1 = "Error while Saving sdk status "
            java.lang.String r2 = "SdkListHelper"
            r3 = 6
            com.google.android.gms.measurement.internal.Z.p(r1, r5, r2, r3)
        L17:
            if (r0 == 0) goto L24
            android.content.SharedPreferences r5 = r4.a
            android.content.SharedPreferences$Editor r5 = r5.edit()
            java.lang.String r1 = "OT_INTERNAL_SDK_STATUS_MAP"
            com.google.android.gms.internal.mlkit_vision_document_scanner.L.i(r0, r5, r1)
        L24:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.g.g(java.lang.String):void");
    }

    public final void h(String str, boolean z) {
        try {
            JSONObject jSONObject = new JSONObject(this.a.getString("OT_INTERNAL_SDK_STATUS_MAP", ""));
            if (!jSONObject.has(str) || 2 == jSONObject.getInt(str)) {
                return;
            }
            JSONObject jSONObject2 = this.c;
            jSONObject2.put(str, z ? 1 : 0);
            OTLogger.c("SdkListHelper", 4, "Updated SDK status for  - " + str + " To " + jSONObject2.get(str));
        } catch (JSONException e) {
            Z.p("Error while updating sdk status ", e, "SdkListHelper", 6);
        }
    }
}
