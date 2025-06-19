package com.google.android.gms.internal.ads;

import java.util.Set;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;

/* loaded from: classes2.dex */
public final class Bv extends AbstractC1981ds {
    public static final AtomicReferenceFieldUpdater b = AtomicReferenceFieldUpdater.newUpdater(Dv.class, Set.class, "h");
    public static final AtomicIntegerFieldUpdater c = AtomicIntegerFieldUpdater.newUpdater(Dv.class, "i");

    @Override // com.google.android.gms.internal.ads.AbstractC1981ds
    public final int a(Av av) {
        return c.decrementAndGet(av);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1981ds
    public final void q(Av av, Set set) {
        while (true) {
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = b;
            if (atomicReferenceFieldUpdater.compareAndSet(av, null, set)) {
                return;
            }
            if (atomicReferenceFieldUpdater.get(av) != null && atomicReferenceFieldUpdater.get(av) != null) {
                return;
            }
        }
    }
}
