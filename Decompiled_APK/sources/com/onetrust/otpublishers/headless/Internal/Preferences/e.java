package com.onetrust.otpublishers.headless.Internal.Preferences;

import android.content.Context;
import androidx.annotation.NonNull;
import com.google.android.gms.internal.mlkit_vision_document_scanner.L;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import java.util.Locale;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class e {
    public final d a;
    public final com.google.mlkit.vision.documentscanner.internal.c b;

    public e(@NonNull Context context) {
        d dVar = new d(context);
        this.a = dVar;
        this.b = new com.google.mlkit.vision.documentscanner.internal.c(dVar, 1);
    }

    public final int a(String str) {
        String strJ;
        JSONObject jSONObject;
        if (g(str)) {
            return 1;
        }
        String string = this.a.b().getString("OTT_CONSENT_STATUS", "");
        if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            Locale locale = Locale.ENGLISH;
            String lowerCase = str.toLowerCase(locale);
            try {
                jSONObject = new JSONObject(string.toLowerCase(locale));
            } catch (JSONException unused) {
                jSONObject = null;
            }
            try {
                if (jSONObject.has(lowerCase)) {
                    return jSONObject.getInt(lowerCase);
                }
                return -1;
            } catch (JSONException unused2) {
                strJ = assistantMode.refactored.a.j("error in json parsing for customGroup Value = ", jSONObject);
                OTLogger.c("OTSPUtils", 3, strJ);
                return -1;
            }
        }
        strJ = "customGroup Value not set.";
        OTLogger.c("OTSPUtils", 3, strJ);
        return -1;
    }

    public final JSONObject b() {
        String string = this.a.b().getString("OTT_CULTURE_DOMAIN_DATA", "");
        if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            try {
                return new JSONObject(string);
            } catch (JSONException e) {
                Z.p("error while returning culture domain data, err: ", e, "OneTrust", 6);
            }
        }
        return new JSONObject();
    }

    public final void c(int i) {
        this.a.b().edit().putInt("OTT_DATA_SUBJECT_IDENTIFIER_TYPE", i).apply();
    }

    public final void d(JSONObject jSONObject) {
        OTLogger.c("IAB2V2Flow", 3, "Setting saveDataDeclarationCategories = " + jSONObject.toString());
        L.i(jSONObject, this.a.b().edit(), "OT_DATA_DECLARATION_CATEGORIES");
    }

    public final JSONObject e() {
        try {
            String string = this.a.b().getString("OT_MOBILE_DATA", "");
            if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                return new JSONObject(string);
            }
        } catch (JSONException e) {
            Z.p("error while getting mobile data json, err: ", e, "OneTrust", 6);
        }
        return new JSONObject();
    }

    public final void f(int i) {
        this.a.b().edit().putInt("OT_MIGRATION_STATUS", i).apply();
    }

    public final boolean g(String str) {
        String string = this.a.b().getString("OTT_ALWAYS_ACTIVE_GROUPS", "");
        if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            return false;
        }
        try {
            Locale locale = Locale.ENGLISH;
            return new JSONObject(string.toLowerCase(locale)).has(str.toLowerCase(locale));
        } catch (Exception e) {
            Z.n("Error in getting always active groups ", e, "OTSPUtils", 6);
            return false;
        }
    }

    public final JSONObject h() {
        String string = this.a.b().getString("OT_VENDOR_COUNT_FOR_CATEGORIES", "");
        OTLogger.c("IAB2V2Flow", 3, "Getting vendorCountForCategoryString = " + string);
        if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            try {
                return new JSONObject(string);
            } catch (JSONException e) {
                Z.p("Error on getting vendor count for categories : ", e, "OTSPUtils", 6);
            }
        }
        return new JSONObject();
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0032  */
    /* JADX WARN: Removed duplicated region for block: B:16:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void i(java.lang.String r6) throws java.text.ParseException {
        /*
            r5 = this;
            java.text.SimpleDateFormat r0 = new java.text.SimpleDateFormat
            java.lang.String r1 = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
            r0.<init>(r1)
            java.util.Date r0 = r0.parse(r6)     // Catch: java.lang.Exception -> Lc java.text.ParseException -> L20
            goto L30
        Lc:
            r0 = move-exception
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            java.lang.String r2 = "Error on converting date. Error msg = "
            r1.<init>(r2)
        L14:
            java.lang.String r0 = r0.getMessage()
            r1.append(r0)
            java.lang.String r0 = r1.toString()
            goto L29
        L20:
            r0 = move-exception
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            java.lang.String r2 = "Error on converting tc string date, message = "
            r1.<init>(r2)
            goto L14
        L29:
            r1 = 6
            java.lang.String r2 = "OTUtils"
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r2, r1, r0)
            r0 = 0
        L30:
            if (r0 == 0) goto L69
            com.onetrust.otpublishers.headless.Internal.Preferences.d r1 = r5.a
            android.content.SharedPreferences r1 = r1.b()
            android.content.SharedPreferences$Editor r1 = r1.edit()
            long r2 = r0.getTime()
            java.lang.String r4 = "OT_IAB_TC_STR_CREATED_IN_MILLISECONDS"
            android.content.SharedPreferences$Editor r1 = r1.putLong(r4, r2)
            r1.apply()
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            java.lang.String r2 = "Updating tc string Created date from profile sync value,Date = "
            r1.<init>(r2)
            r1.append(r6)
            java.lang.String r6 = " , milliseconds = "
            r1.append(r6)
            long r2 = r0.getTime()
            r1.append(r2)
            java.lang.String r6 = r1.toString()
            java.lang.String r0 = "TCStringDate"
            r1 = 2
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r0, r1, r6)
        L69:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Preferences.e.i(java.lang.String):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0032  */
    /* JADX WARN: Removed duplicated region for block: B:16:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void j(java.lang.String r6) throws java.text.ParseException {
        /*
            r5 = this;
            java.text.SimpleDateFormat r0 = new java.text.SimpleDateFormat
            java.lang.String r1 = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
            r0.<init>(r1)
            java.util.Date r0 = r0.parse(r6)     // Catch: java.lang.Exception -> Lc java.text.ParseException -> L20
            goto L30
        Lc:
            r0 = move-exception
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            java.lang.String r2 = "Error on converting date. Error msg = "
            r1.<init>(r2)
        L14:
            java.lang.String r0 = r0.getMessage()
            r1.append(r0)
            java.lang.String r0 = r1.toString()
            goto L29
        L20:
            r0 = move-exception
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            java.lang.String r2 = "Error on converting tc string date, message = "
            r1.<init>(r2)
            goto L14
        L29:
            r1 = 6
            java.lang.String r2 = "OTUtils"
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r2, r1, r0)
            r0 = 0
        L30:
            if (r0 == 0) goto L69
            com.onetrust.otpublishers.headless.Internal.Preferences.d r1 = r5.a
            android.content.SharedPreferences r1 = r1.b()
            android.content.SharedPreferences$Editor r1 = r1.edit()
            long r2 = r0.getTime()
            java.lang.String r4 = "OT_IAB_TC_STR_LAST_UPDATED_IN_MILLISECONDS"
            android.content.SharedPreferences$Editor r1 = r1.putLong(r4, r2)
            r1.apply()
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            java.lang.String r2 = "Updating tc string updated date from profile sync value,Date = "
            r1.<init>(r2)
            r1.append(r6)
            java.lang.String r6 = " , milliseconds = "
            r1.append(r6)
            long r2 = r0.getTime()
            r1.append(r2)
            java.lang.String r6 = r1.toString()
            java.lang.String r0 = "TCStringDate"
            r1 = 2
            com.onetrust.otpublishers.headless.Internal.Log.OTLogger.c(r0, r1, r6)
        L69:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Preferences.e.j(java.lang.String):void");
    }

    public final void k(String str) {
        this.a.b().edit().putString("OTT_DATA_SUBJECT_IDENTIFIER", str).apply();
    }

    public final boolean l() {
        boolean z = this.a.b().getBoolean("IS_IAB2_V2_TEMPLATE_FLAG", false);
        OTLogger.c("IAB2V2Flow", 3, "Is iab2V2TypeFlag = " + z);
        return z;
    }

    public final boolean m() {
        try {
            String string = this.a.b().getString("OTT_PC_DATA", null);
            JSONObject jSONObject = com.onetrust.otpublishers.headless.Internal.a.j(string) ? null : new JSONObject(string);
            if (jSONObject != null) {
                boolean zL = com.onetrust.otpublishers.headless.Internal.a.l(jSONObject.optString("IabType"));
                OTLogger.c("IAB2V2Flow", 3, "Is Iab2v2type = " + zL);
                return zL;
            }
        } catch (JSONException e) {
            Z.p("Error on getting iab type : ", e, "IAB2V2Flow", 6);
        }
        OTLogger.c("IAB2V2Flow", 3, "Iab2v2type false.");
        return false;
    }

    public final boolean n() {
        String string = this.a.b().getString("OT_CONSENT_INTEGRATION_DATA", "");
        try {
        } catch (JSONException e) {
            Z.p("error while returning consent integration data, err: ", e, "OneTrust", 6);
        }
        JSONObject jSONObject = !com.onetrust.otpublishers.headless.Internal.a.j(string) ? new JSONObject(string) : null;
        if (retrofit2.adapter.rxjava3.d.o(jSONObject)) {
            return false;
        }
        return jSONObject.optBoolean("IdentifiedReceiptsAllowed");
    }

    public e(d dVar) {
        this.a = dVar;
        this.b = new com.google.mlkit.vision.documentscanner.internal.c(dVar, 1);
    }
}
