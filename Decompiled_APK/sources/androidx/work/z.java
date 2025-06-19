package androidx.work;

import android.util.Log;

/* loaded from: classes.dex */
public final class z {
    public static final Object b = new Object();
    public static volatile z c;
    public final int a;

    public z(int i) {
        this.a = i;
    }

    public static z c() {
        z zVar;
        synchronized (b) {
            try {
                if (c == null) {
                    c = new z(3);
                }
                zVar = c;
            } catch (Throwable th) {
                throw th;
            }
        }
        return zVar;
    }

    public static String e(String str) {
        int length = str.length();
        StringBuilder sbL = androidx.compose.ui.node.B.l(23, "WM-");
        if (length >= 20) {
            sbL.append(str.substring(0, 20));
        } else {
            sbL.append(str);
        }
        return sbL.toString();
    }

    public final void a(String str, String str2) {
        if (this.a <= 6) {
            Log.e(str, str2);
        }
    }

    public final void b(String str, String str2, Throwable th) {
        if (this.a <= 6) {
            Log.e(str, str2, th);
        }
    }

    public final void d(String str, String str2) {
        if (this.a <= 4) {
            Log.i(str, str2);
        }
    }

    public final void f(String str, String str2) {
        if (this.a <= 5) {
            Log.w(str, str2);
        }
    }
}
