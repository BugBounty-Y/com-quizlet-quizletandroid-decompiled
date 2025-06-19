package com.google.android.gms.internal.ads;

import android.os.SystemClock;

/* loaded from: classes2.dex */
public final class QD implements InterfaceC2650tD {
    public boolean a;
    public long b;
    public long c;
    public C2040f6 d;

    @Override // com.google.android.gms.internal.ads.InterfaceC2650tD
    public final C2040f6 a() {
        return this.d;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2650tD
    public final void b(C2040f6 c2040f6) {
        if (this.a) {
            c(zza());
        }
        this.d = c2040f6;
    }

    public final void c(long j) {
        this.b = j;
        if (this.a) {
            this.c = SystemClock.elapsedRealtime();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2650tD
    public final /* synthetic */ boolean i() {
        return false;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2650tD
    public final long zza() {
        long j = this.b;
        if (!this.a) {
            return j;
        }
        long jElapsedRealtime = SystemClock.elapsedRealtime() - this.c;
        return this.d.a == 1.0f ? Yo.t(jElapsedRealtime) + j : (jElapsedRealtime * r4.c) + j;
    }
}
