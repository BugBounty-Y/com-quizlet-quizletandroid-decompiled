package com.onetrust.otpublishers.headless.Internal.Models;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.annotation.NonNull;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Internal.Preferences.d;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class b {
    public final Context a;
    public final SharedPreferences b;

    public b(@NonNull Context context) {
        this.a = context;
        this.b = new d(context).b();
    }

    public final boolean a(JSONObject jSONObject) {
        long j;
        String str;
        if (!jSONObject.has("LastReconsentDate")) {
            return false;
        }
        String string = !jSONObject.isNull("LastReconsentDate") ? jSONObject.get("LastReconsentDate").toString() : null;
        if (com.onetrust.otpublishers.headless.Internal.a.j(string) || jSONObject.isNull("LastReconsentDate")) {
            return false;
        }
        long j2 = Long.parseLong(string);
        SharedPreferences sharedPreferences = this.b;
        String string2 = sharedPreferences.getString("OTT_LAST_GIVEN_CONSENT", "0");
        long j3 = com.onetrust.otpublishers.headless.Internal.a.j(string2) ? 0L : Long.parseLong(string2);
        String string3 = sharedPreferences.getString("OTT_LAST_RE_CONSENT_DATE", String.valueOf(-1L));
        if (com.onetrust.otpublishers.headless.Internal.a.j(string3)) {
            OTLogger.c("ShowBanner", 4, "Last re-consent date not initialized, it will be set once OT SDK initialized.");
            j = -1;
        } else {
            j = Long.parseLong(string3);
        }
        if (j3 != 0 && j2 > j3) {
            str = "Reconsent Status: Show Banner is enabled for current geolocation rule and user consent is older than lastReconsentDateFromServer";
        } else {
            if (j3 != 0 || j == -1 || j2 <= j) {
                return false;
            }
            str = "Reconsent Status: Show Banner is enabled for current geolocation rule and previous lastReconsentDateFromServer is older than lastReconsentDateFromServer";
        }
        OTLogger.c("ShowBanner", 4, str);
        return true;
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x005f A[Catch: Exception -> 0x003b, TRY_LEAVE, TryCatch #0 {Exception -> 0x003b, blocks: (B:8:0x0029, B:10:0x0035, B:17:0x0059, B:19:0x005f, B:16:0x0054, B:15:0x003e), top: B:149:0x0029, inners: #1 }] */
    /* JADX WARN: Removed duplicated region for block: B:22:0x006a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int b(org.json.JSONObject r22) throws java.lang.NumberFormatException {
        /*
            Method dump skipped, instructions count: 722
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Models.b.b(org.json.JSONObject):int");
    }
}
