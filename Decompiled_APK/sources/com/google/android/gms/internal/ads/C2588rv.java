package com.google.android.gms.internal.ads;

import java.security.AccessController;
import java.security.PrivilegedActionException;
import sun.misc.Unsafe;

/* renamed from: com.google.android.gms.internal.ads.rv, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2588rv extends AbstractC2457os {
    public static final Unsafe b;
    public static final long c;
    public static final long d;
    public static final long e;
    public static final long f;
    public static final long g;

    static {
        Unsafe unsafe;
        try {
            try {
                unsafe = Unsafe.getUnsafe();
            } catch (PrivilegedActionException e2) {
                throw new RuntimeException("Could not initialize intrinsics", e2.getCause());
            }
        } catch (SecurityException unused) {
            unsafe = (Unsafe) AccessController.doPrivileged(new C2803wv());
        }
        try {
            d = unsafe.objectFieldOffset(AbstractC2674tv.class.getDeclaredField("c"));
            c = unsafe.objectFieldOffset(AbstractC2674tv.class.getDeclaredField("b"));
            e = unsafe.objectFieldOffset(AbstractC2674tv.class.getDeclaredField("a"));
            f = unsafe.objectFieldOffset(C2631sv.class.getDeclaredField("a"));
            g = unsafe.objectFieldOffset(C2631sv.class.getDeclaredField("b"));
            b = unsafe;
        } catch (NoSuchFieldException e3) {
            throw new RuntimeException(e3);
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2457os
    public final boolean A(AbstractC2674tv abstractC2674tv, C2631sv c2631sv, C2631sv c2631sv2) {
        return AbstractC2760vv.a(b, abstractC2674tv, d, c2631sv, c2631sv2);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2457os
    public final C2331lv f(AbstractC2460ov abstractC2460ov) {
        C2331lv c2331lv;
        C2331lv c2331lv2 = C2331lv.d;
        do {
            c2331lv = abstractC2460ov.b;
            if (c2331lv2 == c2331lv) {
                break;
            }
        } while (!y(abstractC2460ov, c2331lv, c2331lv2));
        return c2331lv;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2457os
    public final C2631sv p(AbstractC2460ov abstractC2460ov) {
        C2631sv c2631sv;
        C2631sv c2631sv2 = C2631sv.c;
        do {
            c2631sv = abstractC2460ov.c;
            if (c2631sv2 == c2631sv) {
                break;
            }
        } while (!A(abstractC2460ov, c2631sv, c2631sv2));
        return c2631sv;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2457os
    public final void t(C2631sv c2631sv, C2631sv c2631sv2) {
        b.putObject(c2631sv, g, c2631sv2);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2457os
    public final void x(C2631sv c2631sv, Thread thread) {
        b.putObject(c2631sv, f, thread);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2457os
    public final boolean y(AbstractC2460ov abstractC2460ov, C2331lv c2331lv, C2331lv c2331lv2) {
        return AbstractC2760vv.a(b, abstractC2460ov, c, c2331lv, c2331lv2);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2457os
    public final boolean z(AbstractC2674tv abstractC2674tv, Object obj, Object obj2) {
        return AbstractC2760vv.a(b, abstractC2674tv, e, obj, obj2);
    }
}
