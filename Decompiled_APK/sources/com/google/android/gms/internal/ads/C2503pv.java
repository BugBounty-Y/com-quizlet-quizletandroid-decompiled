package com.google.android.gms.internal.ads;

import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;

/* renamed from: com.google.android.gms.internal.ads.pv, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2503pv extends AbstractC2457os {
    public static final AtomicReferenceFieldUpdater b = AtomicReferenceFieldUpdater.newUpdater(C2631sv.class, Thread.class, "a");
    public static final AtomicReferenceFieldUpdater c = AtomicReferenceFieldUpdater.newUpdater(C2631sv.class, C2631sv.class, "b");
    public static final AtomicReferenceFieldUpdater d = AtomicReferenceFieldUpdater.newUpdater(AbstractC2674tv.class, C2631sv.class, "c");
    public static final AtomicReferenceFieldUpdater e = AtomicReferenceFieldUpdater.newUpdater(AbstractC2674tv.class, C2331lv.class, "b");
    public static final AtomicReferenceFieldUpdater f = AtomicReferenceFieldUpdater.newUpdater(AbstractC2674tv.class, Object.class, "a");

    @Override // com.google.android.gms.internal.ads.AbstractC2457os
    public final boolean A(AbstractC2674tv abstractC2674tv, C2631sv c2631sv, C2631sv c2631sv2) {
        return AbstractC2543qs.j(d, abstractC2674tv, c2631sv, c2631sv2);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2457os
    public final C2331lv f(AbstractC2460ov abstractC2460ov) {
        return (C2331lv) e.getAndSet(abstractC2460ov, C2331lv.d);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2457os
    public final C2631sv p(AbstractC2460ov abstractC2460ov) {
        return (C2631sv) d.getAndSet(abstractC2460ov, C2631sv.c);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2457os
    public final void t(C2631sv c2631sv, C2631sv c2631sv2) {
        c.lazySet(c2631sv, c2631sv2);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2457os
    public final void x(C2631sv c2631sv, Thread thread) {
        b.lazySet(c2631sv, thread);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2457os
    public final boolean y(AbstractC2460ov abstractC2460ov, C2331lv c2331lv, C2331lv c2331lv2) {
        return AbstractC2543qs.j(e, abstractC2460ov, c2331lv, c2331lv2);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2457os
    public final boolean z(AbstractC2674tv abstractC2674tv, Object obj, Object obj2) {
        return AbstractC2543qs.j(f, abstractC2674tv, obj, obj2);
    }
}
