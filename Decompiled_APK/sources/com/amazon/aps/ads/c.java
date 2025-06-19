package com.amazon.aps.ads;

import android.util.Log;
import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes.dex */
public abstract class c {
    public static final boolean a;
    public static int b = 5;

    static {
        try {
            a = Log.isLoggable("test", 7);
        } catch (Throwable unused) {
            a = false;
        }
    }

    public static void a() {
        if (a) {
            AbstractC0147y.k(b);
        }
    }

    public static void b(String str, String str2) {
        if (AbstractC0147y.k(b) != 7) {
            Log.e(str, str2);
        }
    }
}
