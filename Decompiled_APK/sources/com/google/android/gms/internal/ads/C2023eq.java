package com.google.android.gms.internal.ads;

import android.os.Bundle;
import com.google.android.gms.ads.formats.AdManagerAdViewOptions;
import com.google.android.gms.ads.formats.PublisherAdViewOptions;
import com.google.android.gms.ads.internal.client.zzfw;
import com.google.android.gms.ads.internal.client.zzm;
import com.google.android.gms.ads.internal.client.zzx;
import java.util.ArrayList;

/* renamed from: com.google.android.gms.internal.ads.eq, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2023eq {
    public final zzfw a;
    public final zzbmg b;
    public final Ln c;
    public final zzm d;
    public final com.google.android.gms.ads.internal.client.zzr e;
    public final String f;
    public final ArrayList g;
    public final ArrayList h;
    public final zzbfv i;
    public final zzx j;
    public final int k;
    public final AdManagerAdViewOptions l;
    public final PublisherAdViewOptions m;
    public final com.google.android.gms.ads.internal.client.P n;
    public final com.airbnb.lottie.parser.l o;
    public final boolean p;
    public final boolean q;
    public final boolean r;
    public final Bundle s;
    public final com.google.android.gms.ads.internal.client.T t;

    public C2023eq(C1979dq c1979dq) {
        this.e = c1979dq.b;
        this.f = c1979dq.c;
        this.t = c1979dq.u;
        zzm zzmVar = c1979dq.a;
        int i = zzmVar.a;
        boolean z = true;
        if (!zzmVar.h && !c1979dq.e) {
            z = false;
        }
        boolean z2 = z;
        int iT = com.google.android.gms.ads.internal.util.F.t(zzmVar.w);
        zzm zzmVar2 = c1979dq.a;
        this.d = new zzm(i, zzmVar.b, zzmVar.c, zzmVar.d, zzmVar.e, zzmVar.f, zzmVar.g, z2, zzmVar.i, zzmVar.j, zzmVar.k, zzmVar.l, zzmVar.m, zzmVar.n, zzmVar.o, zzmVar.p, zzmVar.q, zzmVar.r, zzmVar.s, zzmVar.t, zzmVar.u, zzmVar.v, iT, zzmVar2.x, zzmVar2.y, zzmVar2.z);
        zzfw zzfwVar = c1979dq.d;
        zzbfv zzbfvVar = null;
        if (zzfwVar == null) {
            zzbfv zzbfvVar2 = c1979dq.h;
            zzfwVar = zzbfvVar2 != null ? zzbfvVar2.f : null;
        }
        this.a = zzfwVar;
        ArrayList arrayList = c1979dq.f;
        this.g = arrayList;
        this.h = c1979dq.g;
        if (arrayList != null && (zzbfvVar = c1979dq.h) == null) {
            zzbfvVar = new zzbfv(new com.google.android.gms.ads.formats.b(new com.google.android.gms.ads.formats.b()));
        }
        this.i = zzbfvVar;
        this.j = c1979dq.i;
        this.k = c1979dq.m;
        this.l = c1979dq.j;
        this.m = c1979dq.k;
        this.n = c1979dq.l;
        this.b = c1979dq.n;
        this.o = new com.airbnb.lottie.parser.l(c1979dq.o);
        this.p = c1979dq.p;
        this.q = c1979dq.q;
        this.c = c1979dq.r;
        this.r = c1979dq.s;
        this.s = c1979dq.t;
    }

    public final boolean a() {
        return this.f.matches((String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.o3));
    }
}
