package com.onetrust.otpublishers.headless.Internal.profile;

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import java.util.Locale;
import org.json.JSONException;

/* loaded from: classes2.dex */
public final class b {
    public final com.onetrust.otpublishers.headless.Internal.Preferences.d a;
    public final Context b;

    public b(@NonNull Context context) {
        this.b = context;
        this.a = new com.onetrust.otpublishers.headless.Internal.Preferences.d(context, "OTT_DEFAULT_USER");
    }

    public final void a(String str) {
        if (str == null || com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            return;
        }
        String lowerCase = str.toLowerCase(Locale.US);
        this.a.b().edit().putString("OT_ACTIVE_PROFILE_ID", lowerCase).apply();
        OTLogger.c("MultiProfileFile", 3, "Active profile set to = " + lowerCase);
    }

    public final boolean b(String str, String str2, boolean z, boolean z2) {
        boolean z3;
        boolean z4;
        StringBuilder sbH = AbstractC0147y.h("setProfile called, currentActiveProfileId = ", str, " , newProfileID = ", str2, " , backupDefaultSharedPreferenceData = ");
        sbH.append(z);
        sbH.append(", restoreDefaultSharedPreferenceData = ");
        sbH.append(z2);
        OTLogger.c("MultiProfileFile", 3, sbH.toString());
        if (str2 == null || com.onetrust.otpublishers.headless.Internal.a.j(str2)) {
            return false;
        }
        String lowerCase = str2.toLowerCase(Locale.US);
        a aVar = new a(this.b);
        if (lowerCase.equalsIgnoreCase(str)) {
            z4 = false;
            z3 = false;
        } else {
            z3 = z2;
            z4 = z;
        }
        try {
            aVar.d(str, z4, z4, true, true, true, false);
        } catch (Exception e) {
            Z.n("Error on backupDataWithExceptionHandling,Error = ", e, "OTSDKExceptions", 6);
        }
        a(lowerCase);
        try {
            if (!c.d(this.a, str2)) {
                try {
                    aVar.c(lowerCase, z3, true, true);
                } catch (Exception e2) {
                    OTLogger.c("OTSDKExceptions", 6, "Error on restoreDataWithExceptionHandling,Error = " + e2.getMessage());
                }
            }
            return true;
        } catch (JSONException e3) {
            Z.p("Error on updating multi-profile id maps. Error = ", e3, "MultiProfileFile", 6);
            return false;
        }
    }

    public b(Context context, com.onetrust.otpublishers.headless.Internal.Preferences.d dVar) {
        this.b = context;
        this.a = dVar;
    }
}
