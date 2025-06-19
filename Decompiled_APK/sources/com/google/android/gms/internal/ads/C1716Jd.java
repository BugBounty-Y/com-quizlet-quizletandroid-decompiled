package com.google.android.gms.internal.ads;

import android.content.Context;
import android.net.Uri;
import android.os.SystemClock;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;

/* renamed from: com.google.android.gms.internal.ads.Jd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1716Jd implements Fw {
    public final Context a;
    public final C2807wz b;
    public final String c;
    public final int d;
    public final boolean e;
    public InputStream f;
    public boolean g;
    public Uri h;
    public volatile zzbbf i;
    public boolean j = false;
    public boolean k = false;
    public C2891yx l;

    public C1716Jd(Context context, C2807wz c2807wz, String str, int i) {
        this.a = context;
        this.b = c2807wz;
        this.c = str;
        this.d = i;
        new AtomicLong(-1L);
        this.e = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.T1)).booleanValue();
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final Uri a() {
        return this.h;
    }

    public final boolean b() {
        if (!this.e) {
            return false;
        }
        C2601s7 c2601s7 = AbstractC2773w7.u4;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (!((Boolean) rVar.c.a(c2601s7)).booleanValue() || this.j) {
            return ((Boolean) rVar.c.a(AbstractC2773w7.v4)).booleanValue() && !this.k;
        }
        return true;
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final long c(C2891yx c2891yx) throws IOException {
        if (this.g) {
            throw new IOException("Attempt to open an already open CacheDataSource.");
        }
        this.g = true;
        Uri uri = c2891yx.a;
        this.h = uri;
        this.l = c2891yx;
        this.i = zzbbf.a(uri);
        C2601s7 c2601s7 = AbstractC2773w7.r4;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        zzbbc zzbbcVarE = null;
        if (!((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            if (this.i != null) {
                this.i.h = c2891yx.c;
                zzbbf zzbbfVar = this.i;
                String str = this.c;
                zzbbfVar.i = str != null ? str : "";
                this.i.j = this.d;
                zzbbcVarE = com.google.android.gms.ads.internal.j.C.j.e(this.i);
            }
            if (zzbbcVarE != null && zzbbcVarE.b()) {
                this.j = zzbbcVarE.g();
                this.k = zzbbcVarE.c();
                if (!b()) {
                    this.f = zzbbcVarE.a();
                    return -1L;
                }
            }
        } else if (this.i != null) {
            this.i.h = c2891yx.c;
            zzbbf zzbbfVar2 = this.i;
            String str2 = this.c;
            zzbbfVar2.i = str2 != null ? str2 : "";
            this.i.j = this.d;
            long jLongValue = (this.i.g ? (Long) rVar.c.a(AbstractC2773w7.t4) : (Long) rVar.c.a(AbstractC2773w7.s4)).longValue();
            com.google.android.gms.ads.internal.j.C.k.getClass();
            SystemClock.elapsedRealtime();
            C2257k6 c2257k6O = C1.o(this.a, this.i);
            try {
                try {
                    try {
                        C2343m6 c2343m6 = (C2343m6) c2257k6O.a.get(jLongValue, TimeUnit.MILLISECONDS);
                        c2343m6.getClass();
                        this.j = c2343m6.c;
                        this.k = c2343m6.e;
                        if (!b()) {
                            this.f = c2343m6.a;
                        }
                    } catch (InterruptedException unused) {
                        c2257k6O.cancel(false);
                        Thread.currentThread().interrupt();
                    }
                } catch (ExecutionException | TimeoutException unused2) {
                    c2257k6O.cancel(false);
                }
            } catch (Throwable unused3) {
            }
            com.google.android.gms.ads.internal.j.C.k.getClass();
            SystemClock.elapsedRealtime();
            throw null;
        }
        if (this.i != null) {
            Map map = c2891yx.b;
            long j = c2891yx.c;
            long j2 = c2891yx.d;
            int i = c2891yx.e;
            Uri uri2 = Uri.parse(this.i.a);
            if (uri2 == null) {
                throw new IllegalStateException("The uri must be set.");
            }
            this.l = new C2891yx(uri2, map, j, j2, i);
        }
        return this.b.c(this.l);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2779wD
    public final int d(int i, byte[] bArr, int i2) throws IOException {
        if (!this.g) {
            throw new IOException("Attempt to read closed CacheDataSource.");
        }
        InputStream inputStream = this.f;
        return inputStream != null ? inputStream.read(bArr, i, i2) : this.b.d(i, bArr, i2);
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final void j() throws IOException {
        if (!this.g) {
            throw new IOException("Attempt to close an already closed CacheDataSource.");
        }
        this.g = false;
        this.h = null;
        InputStream inputStream = this.f;
        if (inputStream == null) {
            this.b.j();
        } else {
            com.google.android.gms.common.util.c.d(inputStream);
            this.f = null;
        }
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final void m(FC fc) {
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final /* synthetic */ Map zze() {
        return Collections.EMPTY_MAP;
    }
}
