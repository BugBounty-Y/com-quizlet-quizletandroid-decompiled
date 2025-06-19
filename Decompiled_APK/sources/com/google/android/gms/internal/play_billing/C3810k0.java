package com.google.android.gms.internal.play_billing;

import java.security.AccessController;
import java.security.PrivilegedActionException;
import sun.misc.Unsafe;

/* renamed from: com.google.android.gms.internal.play_billing.k0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3810k0 extends Z0 {
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
            unsafe = (Unsafe) AccessController.doPrivileged(new C3807j0());
        }
        try {
            d = unsafe.objectFieldOffset(AbstractC3816m0.class.getDeclaredField("c"));
            c = unsafe.objectFieldOffset(AbstractC3816m0.class.getDeclaredField("b"));
            e = unsafe.objectFieldOffset(AbstractC3816m0.class.getDeclaredField("a"));
            f = unsafe.objectFieldOffset(C3813l0.class.getDeclaredField("a"));
            g = unsafe.objectFieldOffset(C3813l0.class.getDeclaredField("b"));
            b = unsafe;
        } catch (NoSuchFieldException e3) {
            throw new RuntimeException(e3);
        }
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final boolean A(AbstractC3816m0 abstractC3816m0, C3792e0 c3792e0, C3792e0 c3792e02) {
        return AbstractC3825p0.a(b, abstractC3816m0, c, c3792e0, c3792e02);
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final boolean E(AbstractC3816m0 abstractC3816m0, Object obj, Object obj2) {
        return AbstractC3825p0.a(b, abstractC3816m0, e, obj, obj2);
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final boolean G(AbstractC3816m0 abstractC3816m0, C3813l0 c3813l0, C3813l0 c3813l02) {
        return AbstractC3825p0.a(b, abstractC3816m0, d, c3813l0, c3813l02);
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final C3792e0 e(AbstractC3816m0 abstractC3816m0) {
        C3792e0 c3792e0;
        C3792e0 c3792e02 = C3792e0.d;
        do {
            c3792e0 = abstractC3816m0.b;
            if (c3792e02 == c3792e0) {
                break;
            }
        } while (!A(abstractC3816m0, c3792e0, c3792e02));
        return c3792e0;
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final C3813l0 p(AbstractC3816m0 abstractC3816m0) {
        C3813l0 c3813l0;
        C3813l0 c3813l02 = C3813l0.c;
        do {
            c3813l0 = abstractC3816m0.c;
            if (c3813l02 == c3813l0) {
                break;
            }
        } while (!G(abstractC3816m0, c3813l0, c3813l02));
        return c3813l0;
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final void t(C3813l0 c3813l0, C3813l0 c3813l02) {
        b.putObject(c3813l0, g, c3813l02);
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final void v(C3813l0 c3813l0, Thread thread) {
        b.putObject(c3813l0, f, thread);
    }
}
