package com.onetrust.otpublishers.headless.Internal.Helper;

import android.content.Context;
import androidx.annotation.NonNull;
import com.appsflyer.AdRevenueScheme;
import com.google.android.gms.internal.mlkit_vision_document_scanner.L;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.DataModel.OTGeolocationModel;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class v {
    public final com.onetrust.otpublishers.headless.Internal.Preferences.d a;

    public v(@NonNull Context context) {
        this.a = new com.onetrust.otpublishers.headless.Internal.Preferences.d(context);
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x002c  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0051 A[RETURN] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.onetrust.otpublishers.headless.Public.DataModel.OTGeolocationModel a(int r5) {
        /*
            r4 = this;
            com.onetrust.otpublishers.headless.Internal.Preferences.d r0 = r4.a
            r1 = 1
            java.lang.String r2 = ""
            if (r5 != r1) goto L12
            android.content.SharedPreferences r5 = r0.b()
            java.lang.String r0 = "OTT_USER_CONSENT_LOCATION"
        Ld:
            java.lang.String r2 = r5.getString(r0, r2)
            goto L26
        L12:
            r1 = 2
            if (r5 != r1) goto L1c
            android.content.SharedPreferences r5 = r0.b()
            java.lang.String r0 = "OT_DATA_DOWNLOADED_GEO_LOCATION"
            goto Ld
        L1c:
            r1 = 3
            if (r5 != r1) goto L26
            android.content.SharedPreferences r5 = r0.b()
            java.lang.String r0 = "OT_CONSENTED_LOCATION"
            goto Ld
        L26:
            boolean r5 = com.onetrust.otpublishers.headless.Internal.a.j(r2)
            if (r5 != 0) goto L51
            com.onetrust.otpublishers.headless.Public.DataModel.OTGeolocationModel r5 = new com.onetrust.otpublishers.headless.Public.DataModel.OTGeolocationModel
            r5.<init>()
            org.json.JSONObject r0 = new org.json.JSONObject     // Catch: org.json.JSONException -> L47
            r0.<init>(r2)     // Catch: org.json.JSONException -> L47
            java.lang.String r1 = "country"
            java.lang.String r1 = r0.optString(r1)     // Catch: org.json.JSONException -> L47
            r5.country = r1     // Catch: org.json.JSONException -> L47
            java.lang.String r1 = "state"
            java.lang.String r0 = r0.optString(r1)     // Catch: org.json.JSONException -> L47
            r5.state = r0     // Catch: org.json.JSONException -> L47
            return r5
        L47:
            r0 = move-exception
            java.lang.String r1 = "error in formatting ott data with err = "
            java.lang.String r2 = "GLDataHandler"
            r3 = 6
            com.google.android.gms.measurement.internal.Z.p(r1, r0, r2, r3)
            return r5
        L51:
            r5 = 0
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Helper.v.a(int):com.onetrust.otpublishers.headless.Public.DataModel.OTGeolocationModel");
    }

    public final OTGeolocationModel b(int i, String str, String str2) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        jSONObject.put(AdRevenueScheme.COUNTRY, str);
        jSONObject.put("state", str2);
        com.onetrust.otpublishers.headless.Internal.Preferences.d dVar = this.a;
        if (i == 1) {
            L.i(jSONObject, dVar.b().edit(), "OTT_USER_CONSENT_LOCATION");
        } else if (i == 2) {
            L.i(jSONObject, dVar.b().edit(), "OT_DATA_DOWNLOADED_GEO_LOCATION");
        } else if (i == 3) {
            L.i(jSONObject, dVar.b().edit(), "OT_CONSENTED_LOCATION");
        }
        String string = jSONObject.toString();
        if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
            return null;
        }
        OTGeolocationModel oTGeolocationModel = new OTGeolocationModel();
        try {
            JSONObject jSONObject2 = new JSONObject(string);
            oTGeolocationModel.country = jSONObject2.optString(AdRevenueScheme.COUNTRY);
            oTGeolocationModel.state = jSONObject2.optString("state");
            return oTGeolocationModel;
        } catch (JSONException e) {
            Z.p("error in formatting ott data with err = ", e, "GLDataHandler", 6);
            return oTGeolocationModel;
        }
    }

    public final boolean c() throws JSONException {
        OTGeolocationModel oTGeolocationModelA = a(2);
        if (oTGeolocationModelA == null) {
            return false;
        }
        b(3, oTGeolocationModelA.country, oTGeolocationModelA.state);
        OTLogger.c("GLDataHandler", 4, "Consent given location saved as country:" + oTGeolocationModelA.country + " state:" + oTGeolocationModelA.state);
        return true;
    }
}
