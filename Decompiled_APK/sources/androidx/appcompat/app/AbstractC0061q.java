package androidx.appcompat.app;

import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import androidx.collection.C0204b;
import androidx.collection.C0209g;
import java.lang.ref.WeakReference;

/* renamed from: androidx.appcompat.app.q, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0061q {
    public static final ExecutorC0060p a = new ExecutorC0060p(new androidx.camera.core.impl.utils.executor.a(1));
    public static int b = -100;
    public static androidx.core.os.f c = null;
    public static androidx.core.os.f d = null;
    public static Boolean e = null;
    public static boolean f = false;
    public static final C0209g g = new C0209g(0);
    public static final Object h = new Object();
    public static final Object i = new Object();

    public static boolean c(Context context) {
        if (e == null) {
            try {
                int i2 = I.a;
                Bundle bundle = context.getPackageManager().getServiceInfo(new ComponentName(context, (Class<?>) I.class), H.a() | 128).metaData;
                if (bundle != null) {
                    e = Boolean.valueOf(bundle.getBoolean("autoStoreLocales"));
                }
            } catch (PackageManager.NameNotFoundException unused) {
                e = Boolean.FALSE;
            }
        }
        return e.booleanValue();
    }

    public static void f(B b2) {
        synchronized (h) {
            try {
                C0209g c0209g = g;
                c0209g.getClass();
                C0204b c0204b = new C0204b(c0209g);
                while (c0204b.hasNext()) {
                    AbstractC0061q abstractC0061q = (AbstractC0061q) ((WeakReference) c0204b.next()).get();
                    if (abstractC0061q == b2 || abstractC0061q == null) {
                        c0204b.remove();
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public static void k(int i2) {
        if ((i2 == -1 || i2 == 0 || i2 == 1 || i2 == 2 || i2 == 3) && b != i2) {
            b = i2;
            synchronized (h) {
                try {
                    C0209g c0209g = g;
                    c0209g.getClass();
                    C0204b c0204b = new C0204b(c0209g);
                    while (c0204b.hasNext()) {
                        AbstractC0061q abstractC0061q = (AbstractC0061q) ((WeakReference) c0204b.next()).get();
                        if (abstractC0061q != null) {
                            ((B) abstractC0061q).m(true, true);
                        }
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
    }

    public abstract void a();

    public abstract void b();

    public abstract void d();

    public abstract void e();

    public abstract boolean g(int i2);

    public abstract void h(int i2);

    public abstract void i(View view);

    public abstract void j(View view, ViewGroup.LayoutParams layoutParams);

    public abstract void l(CharSequence charSequence);
}
