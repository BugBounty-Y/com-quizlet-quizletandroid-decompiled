package com.google.android.gms.internal.ads;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.concurrent.Callable;

/* renamed from: com.google.android.gms.internal.ads.s5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractCallableC2599s5 implements Callable {
    public final Z4 a;
    public final String b;
    public final String c;
    public final C1864b4 d;
    public Method e;
    public final int f;
    public final int g;

    public AbstractCallableC2599s5(Z4 z4, String str, String str2, C1864b4 c1864b4, int i, int i2) {
        this.a = z4;
        this.b = str;
        this.c = str2;
        this.d = c1864b4;
        this.f = i;
        this.g = i2;
    }

    public abstract void a();

    @Override // java.util.concurrent.Callable
    public final Object call() {
        int i;
        try {
            long jNanoTime = System.nanoTime();
            Z4 z4 = this.a;
            Method methodD = z4.d(this.b, this.c);
            this.e = methodD;
            if (methodD == null) {
                return null;
            }
            a();
            M4 m4 = z4.k;
            if (m4 == null || (i = this.f) == Integer.MIN_VALUE) {
                return null;
            }
            m4.a(this.g, i, (System.nanoTime() - jNanoTime) / 1000, null, null);
            return null;
        } catch (IllegalAccessException | InvocationTargetException unused) {
            return null;
        }
    }
}
