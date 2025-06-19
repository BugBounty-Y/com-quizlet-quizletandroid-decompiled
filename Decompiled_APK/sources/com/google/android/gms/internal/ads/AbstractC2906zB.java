package com.google.android.gms.internal.ads;

import java.nio.ByteBuffer;
import java.security.AccessController;
import sun.misc.Unsafe;

/* renamed from: com.google.android.gms.internal.ads.zB, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2906zB {
    public static final Unsafe a;
    public static final Class b;
    public static final AbstractC2863yB c;
    public static final boolean d;
    public static final boolean e;
    public static final long f;
    public static final long g;
    public static final boolean h;

    /* JADX WARN: Removed duplicated region for block: B:26:0x007d  */
    /* JADX WARN: Removed duplicated region for block: B:4:0x001c  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x016c A[PHI: r0
  0x016c: PHI (r0v46 java.lang.reflect.Field) = (r0v36 java.lang.reflect.Field), (r0v38 java.lang.reflect.Field) binds: [B:44:0x015c, B:50:0x016a] A[DONT_GENERATE, DONT_INLINE]] */
    static {
        /*
            Method dump skipped, instructions count: 400
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.AbstractC2906zB.<clinit>():void");
    }

    public static int a(Class cls) {
        if (e) {
            return ((Unsafe) c.a).arrayBaseOffset(cls);
        }
        return -1;
    }

    public static void b(Class cls) {
        if (e) {
            ((Unsafe) c.a).arrayIndexScale(cls);
        }
    }

    public static void c(Object obj, long j, byte b2) {
        Unsafe unsafe = (Unsafe) c.a;
        long j2 = (-4) & j;
        int i = unsafe.getInt(obj, j2);
        int i2 = ((~((int) j)) & 3) << 3;
        unsafe.putInt(obj, j2, ((255 & b2) << i2) | (i & (~(255 << i2))));
    }

    public static void d(Object obj, long j, byte b2) {
        Unsafe unsafe = (Unsafe) c.a;
        long j2 = (-4) & j;
        int i = (((int) j) & 3) << 3;
        unsafe.putInt(obj, j2, ((255 & b2) << i) | (unsafe.getInt(obj, j2) & (~(255 << i))));
    }

    public static int e(long j, Object obj) {
        return ((Unsafe) c.a).getInt(obj, j);
    }

    public static long f(ByteBuffer byteBuffer) {
        return ((Unsafe) c.a).getLong(byteBuffer, g);
    }

    public static long g(long j, Object obj) {
        return ((Unsafe) c.a).getLong(obj, j);
    }

    public static Object h(Class cls) {
        try {
            return a.allocateInstance(cls);
        } catch (InstantiationException e2) {
            throw new IllegalStateException(e2);
        }
    }

    public static Object i(long j, Object obj) {
        return ((Unsafe) c.a).getObject(obj, j);
    }

    public static Unsafe j() {
        try {
            return (Unsafe) AccessController.doPrivileged(new C2734vB());
        } catch (Throwable unused) {
            return null;
        }
    }

    public static void k(byte[] bArr, byte b2, long j) {
        c.c1(bArr, f + j, b2);
    }

    public static void l(long j, Object obj, int i) {
        ((Unsafe) c.a).putInt(obj, j, i);
    }

    public static void m(Object obj, long j, long j2) {
        ((Unsafe) c.a).putLong(obj, j, j2);
    }

    public static void n(long j, Object obj, Object obj2) {
        ((Unsafe) c.a).putObject(obj, j, obj2);
    }

    public static /* bridge */ /* synthetic */ boolean o(long j, Object obj) {
        return ((byte) ((((Unsafe) c.a).getInt(obj, (-4) & j) >>> ((int) (((~j) & 3) << 3))) & 255)) != 0;
    }

    public static /* bridge */ /* synthetic */ boolean p(long j, Object obj) {
        return ((byte) ((((Unsafe) c.a).getInt(obj, (-4) & j) >>> ((int) ((j & 3) << 3))) & 255)) != 0;
    }

    public static boolean q(Class cls) {
        int i = AbstractC2733vA.a;
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
}
