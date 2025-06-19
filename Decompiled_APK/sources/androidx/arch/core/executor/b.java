package androidx.arch.core.executor;

import android.os.Looper;
import com.facebook.appevents.m;

/* loaded from: classes.dex */
public final class b extends m {
    public static volatile b b;
    public static final a c = new a(0);
    public final e a = new e();

    public static b p() {
        if (b != null) {
            return b;
        }
        synchronized (b.class) {
            try {
                if (b == null) {
                    b = new b();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return b;
    }

    public final void q(Runnable runnable) {
        e eVar = this.a;
        if (eVar.c == null) {
            synchronized (eVar.a) {
                try {
                    if (eVar.c == null) {
                        eVar.c = e.p(Looper.getMainLooper());
                    }
                } finally {
                }
            }
        }
        eVar.c.post(runnable);
    }
}
