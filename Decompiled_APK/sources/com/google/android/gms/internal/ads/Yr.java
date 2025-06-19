package com.google.android.gms.internal.ads;

import java.lang.ref.WeakReference;
import java.util.Collections;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class Yr {
    public static final Yr d;
    public WeakReference a;
    public boolean b;
    public boolean c;

    static {
        Yr yr = new Yr();
        yr.b = false;
        yr.c = false;
        d = yr;
    }

    public final void a(boolean z, boolean z2) {
        if ((z2 || z) == (this.c || this.b)) {
            return;
        }
        Iterator it2 = Collections.unmodifiableCollection(Qr.c.a).iterator();
        while (it2.hasNext()) {
            Zr zr = ((Hr) it2.next()).d;
            boolean z3 = z2 || z;
            if (zr.b.get() != 0) {
                AbstractC1795We.o(zr.a(), "setDeviceLockState", true != z3 ? "unlocked" : "locked");
            }
        }
    }
}
