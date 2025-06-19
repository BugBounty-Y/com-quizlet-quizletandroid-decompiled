package com.onetrust.otpublishers.headless.gpp.templates;

import android.content.Context;
import androidx.annotation.NonNull;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.Keys.OTGppKeys;

/* loaded from: classes2.dex */
public final class a {
    public final Context a;

    public a(@NonNull Context context) {
        this.a = context;
    }

    public final void a() {
        Context context = this.a;
        try {
            com.onetrust.otpublishers.headless.gpp.d dVar = new com.onetrust.otpublishers.headless.gpp.d(context);
            if (dVar.d("CPRA") && dVar.d("CCPA")) {
                return;
            }
            String strB = b();
            OTLogger.c("OneTrust", 4, "Gpp - California/CPRA String : " + strB);
            if (com.onetrust.otpublishers.headless.Internal.a.j(strB)) {
                return;
            }
            new com.onetrust.otpublishers.headless.Internal.Preferences.a(context).c(OTGppKeys.IAB_GPP_CALIFORNIA_STRING, strB);
        } catch (Exception e) {
            OTLogger.c("OneTrust", 6, "compute California/CPRA String failed:" + e);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:57:0x020f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.String b() throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 684
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.gpp.templates.a.b():java.lang.String");
    }
}
