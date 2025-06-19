package com.google.android.gms.ads.internal.overlay;

import android.content.Intent;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.NonNull;
import com.google.android.gms.ads.internal.client.InterfaceC1582a;
import com.google.android.gms.ads.internal.client.r;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.ads.internal.zzl;
import com.google.android.gms.common.internal.ReflectedParcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.ads.AbstractC2270kd;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.BinderC2408nm;
import com.google.android.gms.internal.ads.C2058fh;
import com.google.android.gms.internal.ads.C2536ql;
import com.google.android.gms.internal.ads.C2614se;
import com.google.android.gms.internal.ads.C2743ve;
import com.google.android.gms.internal.ads.C2919zi;
import com.google.android.gms.internal.ads.InterfaceC1999e9;
import com.google.android.gms.internal.ads.InterfaceC2043f9;
import com.google.android.gms.internal.ads.InterfaceC2447oi;
import com.google.android.gms.internal.ads.InterfaceC2529qe;
import com.google.android.gms.internal.ads.InterfaceC2783wb;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/* loaded from: classes2.dex */
public final class AdOverlayInfoParcel extends AbstractSafeParcelable implements ReflectedParcelable {

    @NonNull
    public static final Parcelable.Creator<AdOverlayInfoParcel> CREATOR = new android.support.v4.media.a(27);
    public static final AtomicLong y = new AtomicLong(0);
    public static final ConcurrentHashMap z = new ConcurrentHashMap();
    public final zzc a;
    public final InterfaceC1582a b;
    public final j c;
    public final InterfaceC2529qe d;
    public final InterfaceC2043f9 e;
    public final String f;
    public final boolean g;
    public final String h;
    public final c i;
    public final int j;
    public final int k;
    public final String l;
    public final VersionInfoParcel m;
    public final String n;
    public final zzl o;
    public final InterfaceC1999e9 p;
    public final String q;
    public final String r;
    public final String s;
    public final C2058fh t;
    public final InterfaceC2447oi u;
    public final InterfaceC2783wb v;
    public final boolean w;
    public final long x;

    public AdOverlayInfoParcel(InterfaceC1582a interfaceC1582a, j jVar, c cVar, C2743ve c2743ve, boolean z2, int i, VersionInfoParcel versionInfoParcel, InterfaceC2447oi interfaceC2447oi, BinderC2408nm binderC2408nm) {
        this.a = null;
        this.b = interfaceC1582a;
        this.c = jVar;
        this.d = c2743ve;
        this.p = null;
        this.e = null;
        this.f = null;
        this.g = z2;
        this.h = null;
        this.i = cVar;
        this.j = i;
        this.k = 2;
        this.l = null;
        this.m = versionInfoParcel;
        this.n = null;
        this.o = null;
        this.q = null;
        this.r = null;
        this.s = null;
        this.t = null;
        this.u = interfaceC2447oi;
        this.v = binderC2408nm;
        this.w = false;
        this.x = y.getAndIncrement();
    }

    public static AdOverlayInfoParcel a(Intent intent) {
        try {
            Bundle bundleExtra = intent.getBundleExtra("com.google.android.gms.ads.inernal.overlay.AdOverlayInfo");
            bundleExtra.setClassLoader(AdOverlayInfoParcel.class.getClassLoader());
            return (AdOverlayInfoParcel) bundleExtra.getParcelable("com.google.android.gms.ads.inernal.overlay.AdOverlayInfo");
        } catch (Exception e) {
            if (!((Boolean) r.d.c.a(AbstractC2773w7.Qc)).booleanValue()) {
                return null;
            }
            com.google.android.gms.ads.internal.j.C.h.h("AdOverlayInfoParcel.getFromIntent", e);
            return null;
        }
    }

    public static final com.google.android.gms.dynamic.b b(Object obj) {
        if (((Boolean) r.d.c.a(AbstractC2773w7.Qc)).booleanValue()) {
            return null;
        }
        return new com.google.android.gms.dynamic.b(obj);
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.g(parcel, 2, this.a, i);
        InterfaceC1582a interfaceC1582a = this.b;
        AbstractC3489l3.e(parcel, 3, b(interfaceC1582a));
        j jVar = this.c;
        AbstractC3489l3.e(parcel, 4, b(jVar));
        InterfaceC2529qe interfaceC2529qe = this.d;
        AbstractC3489l3.e(parcel, 5, b(interfaceC2529qe));
        InterfaceC2043f9 interfaceC2043f9 = this.e;
        AbstractC3489l3.e(parcel, 6, b(interfaceC2043f9));
        AbstractC3489l3.h(parcel, 7, this.f);
        AbstractC3489l3.m(parcel, 8, 4);
        parcel.writeInt(this.g ? 1 : 0);
        AbstractC3489l3.h(parcel, 9, this.h);
        c cVar = this.i;
        AbstractC3489l3.e(parcel, 10, b(cVar));
        AbstractC3489l3.m(parcel, 11, 4);
        parcel.writeInt(this.j);
        AbstractC3489l3.m(parcel, 12, 4);
        parcel.writeInt(this.k);
        AbstractC3489l3.h(parcel, 13, this.l);
        AbstractC3489l3.g(parcel, 14, this.m, i);
        AbstractC3489l3.h(parcel, 16, this.n);
        AbstractC3489l3.g(parcel, 17, this.o, i);
        InterfaceC1999e9 interfaceC1999e9 = this.p;
        AbstractC3489l3.e(parcel, 18, b(interfaceC1999e9));
        AbstractC3489l3.h(parcel, 19, this.q);
        AbstractC3489l3.h(parcel, 24, this.r);
        AbstractC3489l3.h(parcel, 25, this.s);
        C2058fh c2058fh = this.t;
        AbstractC3489l3.e(parcel, 26, b(c2058fh));
        InterfaceC2447oi interfaceC2447oi = this.u;
        AbstractC3489l3.e(parcel, 27, b(interfaceC2447oi));
        InterfaceC2783wb interfaceC2783wb = this.v;
        AbstractC3489l3.e(parcel, 28, b(interfaceC2783wb));
        AbstractC3489l3.m(parcel, 29, 4);
        parcel.writeInt(this.w ? 1 : 0);
        AbstractC3489l3.m(parcel, 30, 8);
        long j = this.x;
        parcel.writeLong(j);
        AbstractC3489l3.o(iN, parcel);
        if (((Boolean) r.d.c.a(AbstractC2773w7.Qc)).booleanValue()) {
            z.put(Long.valueOf(j), new h(interfaceC1582a, jVar, interfaceC2529qe, interfaceC1999e9, interfaceC2043f9, cVar, c2058fh, interfaceC2447oi, interfaceC2783wb, AbstractC2270kd.d.schedule(new i(j), ((Integer) r2.c.a(AbstractC2773w7.Sc)).intValue(), TimeUnit.SECONDS)));
        }
    }

    public AdOverlayInfoParcel(InterfaceC1582a interfaceC1582a, C2614se c2614se, InterfaceC1999e9 interfaceC1999e9, InterfaceC2043f9 interfaceC2043f9, c cVar, C2743ve c2743ve, boolean z2, int i, String str, VersionInfoParcel versionInfoParcel, InterfaceC2447oi interfaceC2447oi, BinderC2408nm binderC2408nm, boolean z3) {
        this.a = null;
        this.b = interfaceC1582a;
        this.c = c2614se;
        this.d = c2743ve;
        this.p = interfaceC1999e9;
        this.e = interfaceC2043f9;
        this.f = null;
        this.g = z2;
        this.h = null;
        this.i = cVar;
        this.j = i;
        this.k = 3;
        this.l = str;
        this.m = versionInfoParcel;
        this.n = null;
        this.o = null;
        this.q = null;
        this.r = null;
        this.s = null;
        this.t = null;
        this.u = interfaceC2447oi;
        this.v = binderC2408nm;
        this.w = z3;
        this.x = y.getAndIncrement();
    }

    public AdOverlayInfoParcel(InterfaceC1582a interfaceC1582a, C2614se c2614se, InterfaceC1999e9 interfaceC1999e9, InterfaceC2043f9 interfaceC2043f9, c cVar, C2743ve c2743ve, boolean z2, int i, String str, String str2, VersionInfoParcel versionInfoParcel, InterfaceC2447oi interfaceC2447oi, BinderC2408nm binderC2408nm) {
        this.a = null;
        this.b = interfaceC1582a;
        this.c = c2614se;
        this.d = c2743ve;
        this.p = interfaceC1999e9;
        this.e = interfaceC2043f9;
        this.f = str2;
        this.g = z2;
        this.h = str;
        this.i = cVar;
        this.j = i;
        this.k = 3;
        this.l = null;
        this.m = versionInfoParcel;
        this.n = null;
        this.o = null;
        this.q = null;
        this.r = null;
        this.s = null;
        this.t = null;
        this.u = interfaceC2447oi;
        this.v = binderC2408nm;
        this.w = false;
        this.x = y.getAndIncrement();
    }

    public AdOverlayInfoParcel(zzc zzcVar, IBinder iBinder, IBinder iBinder2, IBinder iBinder3, IBinder iBinder4, String str, boolean z2, String str2, IBinder iBinder5, int i, int i2, String str3, VersionInfoParcel versionInfoParcel, String str4, zzl zzlVar, IBinder iBinder6, String str5, String str6, String str7, IBinder iBinder7, IBinder iBinder8, IBinder iBinder9, boolean z3, long j) {
        this.a = zzcVar;
        this.f = str;
        this.g = z2;
        this.h = str2;
        this.j = i;
        this.k = i2;
        this.l = str3;
        this.m = versionInfoParcel;
        this.n = str4;
        this.o = zzlVar;
        this.q = str5;
        this.r = str6;
        this.s = str7;
        this.w = z3;
        this.x = j;
        if (((Boolean) r.d.c.a(AbstractC2773w7.Qc)).booleanValue()) {
            h hVar = (h) z.remove(Long.valueOf(j));
            if (hVar != null) {
                this.b = hVar.a;
                this.c = hVar.b;
                this.d = hVar.c;
                this.p = hVar.d;
                this.e = hVar.e;
                this.t = hVar.g;
                this.u = hVar.h;
                this.v = hVar.i;
                this.i = hVar.f;
                hVar.j.cancel(false);
                return;
            }
            throw new NullPointerException("AdOverlayObjects is null");
        }
        this.b = (InterfaceC1582a) com.google.android.gms.dynamic.b.I3(com.google.android.gms.dynamic.b.v3(iBinder));
        this.c = (j) com.google.android.gms.dynamic.b.I3(com.google.android.gms.dynamic.b.v3(iBinder2));
        this.d = (InterfaceC2529qe) com.google.android.gms.dynamic.b.I3(com.google.android.gms.dynamic.b.v3(iBinder3));
        this.p = (InterfaceC1999e9) com.google.android.gms.dynamic.b.I3(com.google.android.gms.dynamic.b.v3(iBinder6));
        this.e = (InterfaceC2043f9) com.google.android.gms.dynamic.b.I3(com.google.android.gms.dynamic.b.v3(iBinder4));
        this.i = (c) com.google.android.gms.dynamic.b.I3(com.google.android.gms.dynamic.b.v3(iBinder5));
        this.t = (C2058fh) com.google.android.gms.dynamic.b.I3(com.google.android.gms.dynamic.b.v3(iBinder7));
        this.u = (InterfaceC2447oi) com.google.android.gms.dynamic.b.I3(com.google.android.gms.dynamic.b.v3(iBinder8));
        this.v = (InterfaceC2783wb) com.google.android.gms.dynamic.b.I3(com.google.android.gms.dynamic.b.v3(iBinder9));
    }

    public AdOverlayInfoParcel(zzc zzcVar, InterfaceC1582a interfaceC1582a, j jVar, c cVar, VersionInfoParcel versionInfoParcel, C2743ve c2743ve, InterfaceC2447oi interfaceC2447oi, String str) {
        this.a = zzcVar;
        this.b = interfaceC1582a;
        this.c = jVar;
        this.d = c2743ve;
        this.p = null;
        this.e = null;
        this.f = null;
        this.g = false;
        this.h = null;
        this.i = cVar;
        this.j = -1;
        this.k = 4;
        this.l = null;
        this.m = versionInfoParcel;
        this.n = null;
        this.o = null;
        this.q = str;
        this.r = null;
        this.s = null;
        this.t = null;
        this.u = interfaceC2447oi;
        this.v = null;
        this.w = false;
        this.x = y.getAndIncrement();
    }

    public AdOverlayInfoParcel(C2743ve c2743ve, VersionInfoParcel versionInfoParcel, String str, String str2, InterfaceC2783wb interfaceC2783wb) {
        this.a = null;
        this.b = null;
        this.c = null;
        this.d = c2743ve;
        this.p = null;
        this.e = null;
        this.f = null;
        this.g = false;
        this.h = null;
        this.i = null;
        this.j = 14;
        this.k = 5;
        this.l = null;
        this.m = versionInfoParcel;
        this.n = null;
        this.o = null;
        this.q = str;
        this.r = str2;
        this.s = null;
        this.t = null;
        this.u = null;
        this.v = interfaceC2783wb;
        this.w = false;
        this.x = y.getAndIncrement();
    }

    public AdOverlayInfoParcel(C2919zi c2919zi, InterfaceC2529qe interfaceC2529qe, int i, VersionInfoParcel versionInfoParcel, String str, zzl zzlVar, String str2, String str3, String str4, C2058fh c2058fh, BinderC2408nm binderC2408nm, String str5) {
        this.a = null;
        this.b = null;
        this.c = c2919zi;
        this.d = interfaceC2529qe;
        this.p = null;
        this.e = null;
        this.g = false;
        if (((Boolean) r.d.c.a(AbstractC2773w7.O0)).booleanValue()) {
            this.f = null;
            this.h = null;
        } else {
            this.f = str2;
            this.h = str3;
        }
        this.i = null;
        this.j = i;
        this.k = 1;
        this.l = null;
        this.m = versionInfoParcel;
        this.n = str;
        this.o = zzlVar;
        this.q = str5;
        this.r = null;
        this.s = str4;
        this.t = c2058fh;
        this.u = null;
        this.v = binderC2408nm;
        this.w = false;
        this.x = y.getAndIncrement();
    }

    public AdOverlayInfoParcel(C2536ql c2536ql, InterfaceC2529qe interfaceC2529qe, VersionInfoParcel versionInfoParcel) {
        this.c = c2536ql;
        this.d = interfaceC2529qe;
        this.j = 1;
        this.m = versionInfoParcel;
        this.a = null;
        this.b = null;
        this.p = null;
        this.e = null;
        this.f = null;
        this.g = false;
        this.h = null;
        this.i = null;
        this.k = 1;
        this.l = null;
        this.n = null;
        this.o = null;
        this.q = null;
        this.r = null;
        this.s = null;
        this.t = null;
        this.u = null;
        this.v = null;
        this.w = false;
        this.x = y.getAndIncrement();
    }
}
