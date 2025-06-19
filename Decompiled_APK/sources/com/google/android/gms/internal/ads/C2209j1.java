package com.google.android.gms.internal.ads;

import java.io.EOFException;
import java.io.InterruptedIOException;
import java.util.ArrayDeque;

/* renamed from: com.google.android.gms.internal.ads.j1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2209j1 {
    public final byte[] a = new byte[8];
    public final ArrayDeque b = new ArrayDeque();
    public final C2338m1 c = new C2338m1(0);
    public Ts d;
    public int e;
    public int f;
    public long g;

    public final long a(P p, int i) throws EOFException, InterruptedIOException {
        p.h(this.a, 0, i, false);
        long j = 0;
        for (int i2 = 0; i2 < i; i2++) {
            j = (j << 8) | (r0[i2] & 255);
        }
        return j;
    }
}
