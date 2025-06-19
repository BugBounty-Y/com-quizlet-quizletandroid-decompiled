package com.google.android.gms.internal.play_billing;

import java.security.AccessController;
import sun.misc.Unsafe;

/* loaded from: classes2.dex */
public abstract class G1 {
    public static final Unsafe a;
    public static final Class b;
    public static final F1 c;
    public static final boolean d;
    public static final boolean e;
    public static final long f;
    public static final boolean g;

    /* JADX WARN: Removed duplicated region for block: B:26:0x007b  */
    /* JADX WARN: Removed duplicated region for block: B:4:0x001c  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x0168 A[PHI: r0
  0x0168: PHI (r0v41 java.lang.reflect.Field) = (r0v34 java.lang.reflect.Field), (r0v36 java.lang.reflect.Field) binds: [B:44:0x0158, B:50:0x0166] A[DONT_GENERATE, DONT_INLINE]] */
    static {
        /*
            Method dump skipped, instructions count: 388
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.play_billing.G1.<clinit>():void");
    }

    public static void a(Class cls) {
        if (e) {
            c.a.arrayIndexScale(cls);
        }
    }

    public static void b(Object obj, long j, byte b2) {
        F1 f1 = c;
        long j2 = (-4) & j;
        int i = f1.a.getInt(obj, j2);
        int i2 = ((~((int) j)) & 3) << 3;
        f1.a.putInt(obj, j2, ((255 & b2) << i2) | (i & (~(255 << i2))));
    }

    public static void c(Object obj, long j, byte b2) {
        F1 f1 = c;
        long j2 = (-4) & j;
        int i = (((int) j) & 3) << 3;
        f1.a.putInt(obj, j2, ((255 & b2) << i) | (f1.a.getInt(obj, j2) & (~(255 << i))));
    }

    public static int d(long j, Object obj) {
        return c.a.getInt(obj, j);
    }

    public static long e(long j, Object obj) {
        return c.a.getLong(obj, j);
    }

    public static Object f(Class cls) {
        try {
            return a.allocateInstance(cls);
        } catch (InstantiationException e2) {
            throw new IllegalStateException(e2);
        }
    }

    public static Object g(long j, Object obj) {
        return c.a.getObject(obj, j);
    }

    public static Unsafe h() {
        try {
            return (Unsafe) AccessController.doPrivileged(new C1());
        } catch (Throwable unused) {
            return null;
        }
    }

    public static void i(long j, Object obj, int i) {
        c.a.putInt(obj, j, i);
    }

    public static void j(Object obj, long j, long j2) {
        c.a.putLong(obj, j, j2);
    }

    public static void k(long j, Object obj, Object obj2) {
        c.a.putObject(obj, j, obj2);
    }

    public static /* bridge */ /* synthetic */ boolean l(long j, Object obj) {
        return ((byte) ((c.a.getInt(obj, (-4) & j) >>> ((int) (((~j) & 3) << 3))) & 255)) != 0;
    }

    public static /* bridge */ /* synthetic */ boolean m(long j, Object obj) {
        return ((byte) ((c.a.getInt(obj, (-4) & j) >>> ((int) ((j & 3) << 3))) & 255)) != 0;
    }

    public static boolean n(Class cls) {
        int i = R0.a;
        try {
            Class cls2 = b;
            Class cls3 = Boolean.TYPE;
            cls2.getMethod("peekLong", cls, cls3);
            cls2.getMethod("pokeLong", cls, Long.TYPE, cls3);
            Class cls4 = Integer.TYPE;
            cls2.getMethod("pokeInt", cls, cls4, cls3);
            cls2.getMethod("peekInt", cls, cls3);
            cls2.getMethod("pokeByte", cls, Byte.TYPE);
            cls2.getMethod("peekByte", cls);
            cls2.getMethod("pokeByteArray", cls, byte[].class, cls4, cls4);
            cls2.getMethod("peekByteArray", cls, byte[].class, cls4, cls4);
            return true;
        } catch (Throwable unused) {
            return false;
        }
    }

    public static int o(Class cls) {
        if (e) {
            return c.a.arrayBaseOffset(cls);
        }
        return -1;
    }
}
