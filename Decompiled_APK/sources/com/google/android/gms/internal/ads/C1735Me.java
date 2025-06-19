package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.RemoteException;
import com.comscore.streaming.EventType;
import com.google.android.gms.ads.internal.client.zzex;

/* renamed from: com.google.android.gms.internal.ads.Me, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1735Me implements CC {
    public final /* synthetic */ int a;
    public final C1741Ne b;

    public /* synthetic */ C1735Me(C1741Ne c1741Ne, int i) {
        this.a = i;
        this.b = c1741Ne;
    }

    public Jl a() {
        Context contextA = this.b.a();
        Jl jl = new Jl();
        jl.h = 1;
        jl.f = new C2172i6(contextA, com.google.android.gms.ads.internal.j.C.t.o(), (Hl) jl, (Hl) jl);
        return jl;
    }

    public C2281ko b() {
        C2227jd c2227jd = AbstractC2270kd.a;
        AbstractC1981ds.s(c2227jd);
        return new C2281ko(c2227jd, this.b.a(), 1);
    }

    public String c() {
        zzex liteSdkVersion;
        com.google.android.gms.ads.internal.client.Y y = (com.google.android.gms.ads.internal.client.Y) C2326lq.s(this.b.a()).c;
        if (y != null) {
            try {
                liteSdkVersion = y.getLiteSdkVersion();
            } catch (RemoteException unused) {
            }
        } else {
            liteSdkVersion = null;
        }
        if (liteSdkVersion != null) {
            return liteSdkVersion.c;
        }
        return null;
    }

    public C2281ko d() {
        C2227jd c2227jd = AbstractC2270kd.a;
        AbstractC1981ds.s(c2227jd);
        return new C2281ko(c2227jd, this.b.a(), 9);
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                ApplicationInfo applicationInfo = this.b.a().getApplicationInfo();
                AbstractC1981ds.s(applicationInfo);
                return applicationInfo;
            case 1:
                return c();
            case 2:
                C1721Kc c1721KcI = C1721Kc.i(this.b.a());
                return new Fi(10, (com.google.android.gms.common.util.b) c1721KcI.b, (C1697Gc) ((BC) c1721KcI.d).zzb());
            case 3:
                return new C2585rs(this.b.a(), com.google.android.gms.ads.internal.j.C.t.o());
            case 4:
                return new com.google.android.gms.ads.internal.util.q(this.b.a());
            case 5:
                return C2326lq.s(this.b.a());
            case 6:
                return new C2658tf(this.b.a());
            case 7:
                return new C2062fl(this.b.a());
            case 8:
                return new C2750vl(this.b.a());
            case 9:
                String packageName = this.b.a().getPackageName();
                AbstractC1981ds.s(packageName);
                return packageName;
            case 10:
                Context contextA = this.b.a();
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                return new El(contextA, c2227jd, 1);
            case 11:
                return a();
            case 12:
                return new Zl(this.b.a());
            case 13:
                Context contextA2 = this.b.a();
                C2227jd c2227jd2 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd2);
                return new C2107gm(contextA2, c2227jd2);
            case 14:
                return new C2708um(this.b.a());
            case 15:
                return new Ts(this.b.a(), 25);
            case 16:
                return new Un(this.b.a(), 0);
            case 17:
                C2227jd c2227jd3 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd3);
                return new C2281ko(c2227jd3, this.b.a(), 0);
            case 18:
                return b();
            case 19:
                C2227jd c2227jd4 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd4);
                return new C2281ko(c2227jd4, this.b.a(), 2);
            case 20:
                Context contextA3 = this.b.a();
                C2227jd c2227jd5 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd5);
                return new C2281ko(contextA3, c2227jd5, 3);
            case 21:
                C2227jd c2227jd6 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd6);
                return new C2281ko(c2227jd6, this.b.a(), 4);
            case EventType.WINDOW_STATE /* 22 */:
                C2227jd c2227jd7 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd7);
                return new C2281ko(c2227jd7, this.b.a(), 5);
            case EventType.AUDIO /* 23 */:
                C2227jd c2227jd8 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd8);
                return new C2281ko(c2227jd8, this.b.a(), 6);
            case EventType.VIDEO /* 24 */:
                Context contextA4 = this.b.a();
                C2227jd c2227jd9 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd9);
                return new C2281ko(contextA4, c2227jd9, 7);
            case EventType.SUBS /* 25 */:
                C2227jd c2227jd10 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd10);
                return new C2281ko(c2227jd10, this.b.a(), 8);
            case EventType.CDN /* 26 */:
                return d();
            case 27:
                C2227jd c2227jd11 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd11);
                this.b.a();
                return new C2839xo(c2227jd11, 3);
            default:
                return new C2110gp(this.b.a());
        }
    }
}
