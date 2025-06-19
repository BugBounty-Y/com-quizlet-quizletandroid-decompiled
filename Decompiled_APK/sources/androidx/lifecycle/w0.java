package androidx.lifecycle;

import java.util.Iterator;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class w0 {
    public final androidx.lifecycle.viewmodel.internal.d a = new androidx.lifecycle.viewmodel.internal.d();

    public final void w(AutoCloseable closeable, String key) {
        AutoCloseable autoCloseable;
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(closeable, "closeable");
        androidx.lifecycle.viewmodel.internal.d dVar = this.a;
        if (dVar != null) {
            Intrinsics.checkNotNullParameter(key, "key");
            Intrinsics.checkNotNullParameter(closeable, "closeable");
            if (dVar.d) {
                androidx.lifecycle.viewmodel.internal.d.a(closeable);
                return;
            }
            synchronized (dVar.a) {
                autoCloseable = (AutoCloseable) dVar.b.put(key, closeable);
            }
            androidx.lifecycle.viewmodel.internal.d.a(autoCloseable);
        }
    }

    public final void x() {
        androidx.lifecycle.viewmodel.internal.d dVar = this.a;
        if (dVar != null && !dVar.d) {
            dVar.d = true;
            synchronized (dVar.a) {
                try {
                    Iterator it2 = dVar.b.values().iterator();
                    while (it2.hasNext()) {
                        androidx.lifecycle.viewmodel.internal.d.a((AutoCloseable) it2.next());
                    }
                    Iterator it3 = dVar.c.iterator();
                    while (it3.hasNext()) {
                        androidx.lifecycle.viewmodel.internal.d.a((AutoCloseable) it3.next());
                    }
                    dVar.c.clear();
                    Unit unit = Unit.a;
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
        z();
    }

    public final AutoCloseable y(String key) {
        AutoCloseable autoCloseable;
        Intrinsics.checkNotNullParameter(key, "key");
        androidx.lifecycle.viewmodel.internal.d dVar = this.a;
        if (dVar == null) {
            return null;
        }
        Intrinsics.checkNotNullParameter(key, "key");
        synchronized (dVar.a) {
            autoCloseable = (AutoCloseable) dVar.b.get(key);
        }
        return autoCloseable;
    }

    public void z() {
    }
}
