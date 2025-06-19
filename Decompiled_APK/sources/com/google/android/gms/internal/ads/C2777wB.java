package com.google.android.gms.internal.ads;

import libcore.io.Memory;
import sun.misc.Unsafe;

/* renamed from: com.google.android.gms.internal.ads.wB, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2777wB extends AbstractC2863yB {
    @Override // com.google.android.gms.internal.ads.AbstractC2863yB
    public final byte U0(long j) {
        return Memory.peekByte((int) j);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2863yB
    public final double W0(long j, Object obj) {
        return Double.longBitsToDouble(((Unsafe) this.a).getLong(obj, j));
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2863yB
    public final float Y0(long j, Object obj) {
        return Float.intBitsToFloat(((Unsafe) this.a).getInt(obj, j));
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2863yB
    public final void Z0(long j, byte[] bArr, long j2, long j3) {
        Memory.peekByteArray((int) j, bArr, (int) j2, (int) j3);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2863yB
    public final void b1(Object obj, long j, boolean z) {
        if (AbstractC2906zB.h) {
            AbstractC2906zB.c(obj, j, z ? (byte) 1 : (byte) 0);
        } else {
            AbstractC2906zB.d(obj, j, z ? (byte) 1 : (byte) 0);
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2863yB
    public final void c1(Object obj, long j, byte b) {
        if (AbstractC2906zB.h) {
            AbstractC2906zB.c(obj, j, b);
        } else {
            AbstractC2906zB.d(obj, j, b);
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2863yB
    public final void d1(Object obj, long j, double d) {
        ((Unsafe) this.a).putLong(obj, j, Double.doubleToLongBits(d));
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2863yB
    public final void e1(Object obj, long j, float f) {
        ((Unsafe) this.a).putInt(obj, j, Float.floatToIntBits(f));
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2863yB
    public final boolean g1(long j, Object obj) {
        return AbstractC2906zB.h ? AbstractC2906zB.o(j, obj) : AbstractC2906zB.p(j, obj);
    }
}
