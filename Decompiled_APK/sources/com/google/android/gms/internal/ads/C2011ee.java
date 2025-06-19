package com.google.android.gms.internal.ads;

import android.content.Context;
import android.net.Uri;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.atomic.AtomicLong;

/* renamed from: com.google.android.gms.internal.ads.ee, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2011ee extends AbstractC2802wu {
    public final Context e;
    public final Fw f;
    public final String g;
    public final int h;
    public final boolean i;
    public InputStream j;
    public boolean k;
    public Uri l;
    public volatile zzbbf m;
    public boolean n;
    public boolean o;
    public boolean p;
    public boolean q;
    public long r;
    public com.google.common.util.concurrent.e s;
    public final AtomicLong t;
    public final Os u;

    public C2011ee(Context context, Fw fw, String str, int i, FC fc, Os os) {
        super(false);
        this.e = context;
        this.f = fw;
        this.u = os;
        this.g = str;
        this.h = i;
        this.n = false;
        this.o = false;
        this.p = false;
        this.q = false;
        this.r = 0L;
        this.t = new AtomicLong(-1L);
        this.s = null;
        this.i = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.T1)).booleanValue();
        m(fc);
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final Uri a() {
        return this.l;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:94:0x01fe  */
    /* JADX WARN: Type inference failed for: r5v19, types: [com.google.android.gms.ads.internal.j] */
    /* JADX WARN: Type inference failed for: r5v22 */
    /* JADX WARN: Type inference failed for: r5v28 */
    /* JADX WARN: Type inference failed for: r5v40 */
    /* JADX WARN: Type inference failed for: r5v41 */
    @Override // com.google.android.gms.internal.ads.Fw
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final long c(com.google.android.gms.internal.ads.C2891yx r19) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 558
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2011ee.c(com.google.android.gms.internal.ads.yx):long");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2779wD
    public final int d(int i, byte[] bArr, int i2) throws IOException {
        if (!this.k) {
            throw new IOException("Attempt to read closed GcacheDataSource.");
        }
        InputStream inputStream = this.j;
        int iD = inputStream != null ? inputStream.read(bArr, i, i2) : this.f.d(i, bArr, i2);
        if (this.i && this.j == null) {
            return iD;
        }
        e(iD);
        return iD;
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final void j() throws IOException {
        if (!this.k) {
            throw new IOException("Attempt to close an already closed GcacheDataSource.");
        }
        this.k = false;
        this.l = null;
        boolean z = (this.i && this.j == null) ? false : true;
        InputStream inputStream = this.j;
        if (inputStream != null) {
            com.google.android.gms.common.util.c.d(inputStream);
            this.j = null;
        } else {
            this.f.j();
        }
        if (z) {
            b();
        }
    }

    public final boolean q() {
        if (!this.i) {
            return false;
        }
        C2601s7 c2601s7 = AbstractC2773w7.u4;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (!((Boolean) rVar.c.a(c2601s7)).booleanValue() || this.p) {
            return ((Boolean) rVar.c.a(AbstractC2773w7.v4)).booleanValue() && !this.q;
        }
        return true;
    }
}
