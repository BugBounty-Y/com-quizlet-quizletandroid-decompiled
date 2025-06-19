package com.google.firebase.crashlytics.internal.common;

import android.util.Log;
import androidx.camera.camera2.internal.a0;
import com.facebook.internal.H;
import java.io.IOException;

/* loaded from: classes2.dex */
public final class g {
    public static final H d = new H(5);
    public static final a0 e = new a0(14);
    public final com.google.firebase.crashlytics.internal.persistence.c a;
    public String b = null;
    public String c = null;

    public g(com.google.firebase.crashlytics.internal.persistence.c cVar) {
        this.a = cVar;
    }

    public static void a(com.google.firebase.crashlytics.internal.persistence.c cVar, String str, String str2) throws IOException {
        if (str == null || str2 == null) {
            return;
        }
        try {
            cVar.b(str, "aqs.".concat(str2)).createNewFile();
        } catch (IOException e2) {
            Log.w("FirebaseCrashlytics", "Failed to persist App Quality Sessions session id.", e2);
        }
    }
}
