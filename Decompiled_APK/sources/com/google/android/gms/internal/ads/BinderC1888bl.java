package com.google.android.gms.internal.ads;

import android.os.Parcel;
import android.os.SystemClock;

/* renamed from: com.google.android.gms.internal.ads.bl, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC1888bl extends AbstractBinderC2814x5 implements H9 {
    public final /* synthetic */ Object a;
    public final /* synthetic */ String b;
    public final /* synthetic */ long c;
    public final /* synthetic */ Pq d;
    public final /* synthetic */ C2313ld e;
    public final /* synthetic */ C1931cl f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BinderC1888bl(long j, C2313ld c2313ld, C1931cl c1931cl, Pq pq, Object obj, String str) {
        super("com.google.android.gms.ads.internal.initialization.IAdapterInitializationCallback");
        this.a = obj;
        this.b = str;
        this.c = j;
        this.d = pq;
        this.e = c2313ld;
        this.f = c1931cl;
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i == 2) {
            f();
        } else {
            if (i != 3) {
                return false;
            }
            String string = parcel.readString();
            AbstractC2857y5.b(parcel);
            e4(string);
        }
        parcel2.writeNoException();
        return true;
    }

    public final void e4(String str) {
        synchronized (this.a) {
            C1931cl c1931cl = this.f;
            String str2 = this.b;
            com.google.android.gms.ads.internal.j.C.k.getClass();
            c1931cl.d(str2, (int) (SystemClock.elapsedRealtime() - this.c), str, false);
            c1931cl.l.a(str2, "error");
            c1931cl.o.zzb(str2, "error");
            Uq uq = c1931cl.p;
            Pq pq = this.d;
            pq.A(str);
            pq.h(false);
            uq.b(pq.l());
            this.e.c(Boolean.FALSE);
        }
    }

    public final void f() {
        synchronized (this.a) {
            C1931cl c1931cl = this.f;
            String str = this.b;
            com.google.android.gms.ads.internal.j.C.k.getClass();
            c1931cl.d(str, (int) (SystemClock.elapsedRealtime() - this.c), "", true);
            c1931cl.l.c(str);
            c1931cl.o.I(str);
            Uq uq = c1931cl.p;
            Pq pq = this.d;
            pq.h(true);
            uq.b(pq.l());
            this.e.c(Boolean.TRUE);
        }
    }
}
