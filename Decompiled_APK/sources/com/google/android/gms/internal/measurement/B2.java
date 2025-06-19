package com.google.android.gms.internal.measurement;

import sun.misc.Unsafe;

/* loaded from: classes2.dex */
public abstract class B2 {
    public final Unsafe a;

    public B2(Unsafe unsafe) {
        this.a = unsafe;
    }

    public abstract double a(long j, Object obj);

    public abstract float b(long j, Object obj);

    public abstract void c(Object obj, long j, boolean z);

    public abstract void d(Object obj, long j, byte b);

    public abstract void e(Object obj, long j, double d);

    public abstract void f(Object obj, long j, float f);

    public abstract boolean g(long j, Object obj);
}
