package kotlinx.coroutines.sync;

import com.android.billingclient.api.C1472a;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class c extends h implements a {
    public static final /* synthetic */ AtomicReferenceFieldUpdater h = AtomicReferenceFieldUpdater.newUpdater(c.class, Object.class, "owner$volatile");
    private volatile /* synthetic */ Object owner$volatile;

    public c(boolean z) {
        super(1, z ? 1 : 0);
        this.owner$volatile = z ? null : d.a;
    }

    /* JADX WARN: Code restructure failed: missing block: B:11:0x0022, code lost:
    
        r1.m(kotlin.Unit.a, r4.b);
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object d(kotlin.coroutines.h r5) {
        /*
            r4 = this;
            boolean r0 = r4.e()
            if (r0 == 0) goto L9
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        L9:
            kotlin.coroutines.h r0 = kotlin.coroutines.intrinsics.h.b(r5)
            kotlinx.coroutines.l r0 = kotlinx.coroutines.E.t(r0)
            kotlinx.coroutines.sync.b r1 = new kotlinx.coroutines.sync.b     // Catch: java.lang.Throwable -> L48
            r1.<init>(r4, r0)     // Catch: java.lang.Throwable -> L48
        L16:
            java.util.concurrent.atomic.AtomicIntegerFieldUpdater r2 = kotlinx.coroutines.sync.h.g     // Catch: java.lang.Throwable -> L48
            int r2 = r2.getAndDecrement(r4)     // Catch: java.lang.Throwable -> L48
            int r3 = r4.a     // Catch: java.lang.Throwable -> L48
            if (r2 > r3) goto L16
            if (r2 <= 0) goto L2a
            kotlin.Unit r2 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L48
            androidx.navigation.serialization.i r3 = r4.b     // Catch: java.lang.Throwable -> L48
            r1.m(r2, r3)     // Catch: java.lang.Throwable -> L48
            goto L30
        L2a:
            boolean r2 = r4.b(r1)     // Catch: java.lang.Throwable -> L48
            if (r2 == 0) goto L16
        L30:
            java.lang.Object r0 = r0.q()
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            if (r0 != r1) goto L3d
            java.lang.String r2 = "frame"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r2)
        L3d:
            if (r0 != r1) goto L40
            goto L42
        L40:
            kotlin.Unit r0 = kotlin.Unit.a
        L42:
            if (r0 != r1) goto L45
            return r0
        L45:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        L48:
            r5 = move-exception
            r0.C()
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.sync.c.d(kotlin.coroutines.h):java.lang.Object");
    }

    public final boolean e() {
        int i;
        boolean z;
        char c;
        while (true) {
            AtomicIntegerFieldUpdater atomicIntegerFieldUpdater = h.g;
            int i2 = atomicIntegerFieldUpdater.get(this);
            int i3 = this.a;
            if (i2 > i3) {
                do {
                    i = atomicIntegerFieldUpdater.get(this);
                    if (i > i3) {
                    }
                } while (!atomicIntegerFieldUpdater.compareAndSet(this, i, i3));
            } else {
                if (i2 <= 0) {
                    z = false;
                    break;
                }
                if (atomicIntegerFieldUpdater.compareAndSet(this, i2, i2 - 1)) {
                    z = true;
                    break;
                }
            }
        }
        if (z) {
            h.set(this, null);
            c = 0;
        } else {
            c = 1;
        }
        if (c == 0) {
            return true;
        }
        if (c == 1) {
            return false;
        }
        if (c != 2) {
            throw new IllegalStateException("unexpected");
        }
        throw new IllegalStateException("This mutex is already locked by the specified owner: null".toString());
    }

    public final void f(Object obj) {
        while (Math.max(h.g.get(this), 0) == 0) {
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = h;
            Object obj2 = atomicReferenceFieldUpdater.get(this);
            C1472a c1472a = d.a;
            if (obj2 != c1472a) {
                if (obj2 == obj || obj == null) {
                    while (!atomicReferenceFieldUpdater.compareAndSet(this, obj2, c1472a)) {
                        if (atomicReferenceFieldUpdater.get(this) != obj2) {
                            break;
                        }
                    }
                    c();
                    return;
                }
                throw new IllegalStateException(("This mutex is locked by " + obj2 + ", but " + obj + " is expected").toString());
            }
        }
        throw new IllegalStateException("This mutex is not locked");
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Mutex@");
        sb.append(E.r(this));
        sb.append("[isLocked=");
        sb.append(Math.max(h.g.get(this), 0) == 0);
        sb.append(",owner=");
        sb.append(h.get(this));
        sb.append(']');
        return sb.toString();
    }
}
