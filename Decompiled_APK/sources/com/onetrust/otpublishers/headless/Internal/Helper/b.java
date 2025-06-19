package com.onetrust.otpublishers.headless.Internal.Helper;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.annotation.NonNull;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;

/* loaded from: classes2.dex */
public final class b {
    public final com.onetrust.otpublishers.headless.Internal.Preferences.d a;

    public b(@NonNull Context context) {
        this.a = new com.onetrust.otpublishers.headless.Internal.Preferences.d(context);
    }

    public final void a(String str) {
        SharedPreferences.Editor editorEdit;
        int i;
        boolean zEquals = str.equals("OPT_IN");
        com.onetrust.otpublishers.headless.Internal.Preferences.d dVar = this.a;
        if (zEquals) {
            editorEdit = dVar.b().edit();
            i = 1;
        } else {
            if (!str.equals("OPT_OUT")) {
                dVar.b().edit().putInt("OT_AGE_GATE_USER_CONSENT_STATUS", -1).apply();
                OTLogger.c("AgeGateConsentHandler", 3, "Saving Age Gate Consent :" + dVar.b().getInt("OT_AGE_GATE_USER_CONSENT_STATUS", -1));
            }
            editorEdit = dVar.b().edit();
            i = 0;
        }
        editorEdit.putInt("OT_AGE_GATE_USER_CONSENT_STATUS", i).apply();
        OTLogger.c("AgeGateConsentHandler", 3, "Saving Age Gate Consent :" + dVar.b().getInt("OT_AGE_GATE_USER_CONSENT_STATUS", -1));
    }
}
