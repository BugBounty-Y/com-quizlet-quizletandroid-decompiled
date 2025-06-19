package androidx.activity;

import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArrayList;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class D {
    public boolean a;
    public final CopyOnWriteArrayList b = new CopyOnWriteArrayList();
    public C4956o c;

    public D(boolean z) {
        this.a = z;
    }

    public void a() {
    }

    public abstract void b();

    public void c(C0030b backEvent) {
        Intrinsics.checkNotNullParameter(backEvent, "backEvent");
    }

    public void d(C0030b backEvent) {
        Intrinsics.checkNotNullParameter(backEvent, "backEvent");
    }

    public final void e() {
        Iterator it2 = this.b.iterator();
        while (it2.hasNext()) {
            ((InterfaceC0031c) it2.next()).cancel();
        }
    }
}
