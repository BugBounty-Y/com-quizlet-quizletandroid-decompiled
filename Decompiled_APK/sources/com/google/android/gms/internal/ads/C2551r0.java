package com.google.android.gms.internal.ads;

import java.io.EOFException;
import java.io.InterruptedIOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.r0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2551r0 implements U {
    public static final int[] l = {13, 14, 16, 18, 20, 21, 27, 32, 6, 7, 6, 6, 1, 1, 1, 1};
    public static final int[] m = {18, 24, 33, 37, 41, 47, 51, 59, 61, 6, 1, 1, 1, 1, 1, 1};
    public static final byte[] n;
    public static final byte[] o;
    public boolean b;
    public long c;
    public int d;
    public int e;
    public C2695uF g;
    public InterfaceC2380n0 h;
    public Y j;
    public boolean k;
    public final byte[] a = new byte[1];
    public int f = -1;
    public InterfaceC2380n0 i = new T();

    static {
        String str = Yo.a;
        Charset charset = StandardCharsets.UTF_8;
        n = "#!AMR\n".getBytes(charset);
        o = "#!AMR-WB\n".getBytes(charset);
    }

    public final boolean a(P p) throws EOFException, InterruptedIOException {
        p.f = 0;
        byte[] bArr = n;
        int length = bArr.length;
        byte[] bArr2 = new byte[length];
        p.k(bArr2, 0, length, false);
        if (Arrays.equals(bArr2, bArr)) {
            this.b = false;
            p.p(bArr.length);
            return true;
        }
        p.f = 0;
        byte[] bArr3 = o;
        int length2 = bArr3.length;
        byte[] bArr4 = new byte[length2];
        p.k(bArr4, 0, length2, false);
        if (!Arrays.equals(bArr4, bArr3)) {
            return false;
        }
        this.b = true;
        p.p(bArr3.length);
        return true;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final boolean d(V v) {
        return a((P) v);
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void e(W w) {
        C2695uF c2695uF = (C2695uF) w;
        this.g = c2695uF;
        InterfaceC2380n0 interfaceC2380n0Q = c2695uF.q(0, 1);
        this.h = interfaceC2380n0Q;
        this.i = interfaceC2380n0Q;
        c2695uF.n();
    }

    /* JADX WARN: Removed duplicated region for block: B:36:0x009c  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x00a9 A[Catch: EOFException -> 0x00c2, TryCatch #0 {EOFException -> 0x00c2, blocks: (B:27:0x0078, B:29:0x008b, B:43:0x00a9, B:46:0x00b0, B:45:0x00ad, B:60:0x00ed, B:61:0x0105, B:62:0x0106, B:63:0x0116), top: B:72:0x0078 }] */
    /* JADX WARN: Removed duplicated region for block: B:45:0x00ad A[Catch: EOFException -> 0x00c2, TryCatch #0 {EOFException -> 0x00c2, blocks: (B:27:0x0078, B:29:0x008b, B:43:0x00a9, B:46:0x00b0, B:45:0x00ad, B:60:0x00ed, B:61:0x0105, B:62:0x0106, B:63:0x0116), top: B:72:0x0078 }] */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00b8  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00c2  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00c4  */
    @Override // com.google.android.gms.internal.ads.U
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int f(com.google.android.gms.internal.ads.V r21, androidx.compose.foundation.lazy.layout.C0429a r22) throws com.google.android.gms.internal.ads.zzaz {
        /*
            Method dump skipped, instructions count: 305
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2551r0.f(com.google.android.gms.internal.ads.V, androidx.compose.foundation.lazy.layout.a):int");
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void h(long j, long j2) {
        this.c = 0L;
        this.d = 0;
        this.e = 0;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final List j() {
        C2244ju c2244ju = AbstractC2330lu.b;
        return Bu.e;
    }
}
