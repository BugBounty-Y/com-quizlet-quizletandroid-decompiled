package com.google.android.gms.ads.nonagon.signalgeneration;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.internal.ads.AbstractC1981ds;
import com.google.android.gms.internal.ads.AbstractC2270kd;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.BC;
import com.google.android.gms.internal.ads.C1729Le;
import com.google.android.gms.internal.ads.C1735Me;
import com.google.android.gms.internal.ads.C1741Ne;
import com.google.android.gms.internal.ads.C1760Qf;
import com.google.android.gms.internal.ads.C1765Re;
import com.google.android.gms.internal.ads.C2067fq;
import com.google.android.gms.internal.ads.C2195in;
import com.google.android.gms.internal.ads.C2227jd;
import com.google.android.gms.internal.ads.C2280kn;
import com.google.android.gms.internal.ads.C2412nq;
import com.google.android.gms.internal.ads.C2542qr;
import com.google.android.gms.internal.ads.C2584rr;
import com.google.android.gms.internal.ads.C2601s7;
import com.google.android.gms.internal.ads.C2923zm;
import com.google.android.gms.internal.ads.CC;
import com.google.android.gms.internal.ads.DC;
import com.google.android.gms.internal.ads.Ek;
import com.google.android.gms.internal.ads.HC;
import com.google.android.gms.internal.ads.InterfaceC2488pg;
import com.google.android.gms.internal.ads.Kk;
import com.google.android.gms.internal.ads.Lq;
import com.google.android.gms.internal.ads.P4;
import com.google.android.gms.internal.ads.Tg;
import com.google.android.gms.internal.ads.Tq;
import com.google.android.gms.internal.ads.Vh;
import com.google.android.gms.internal.ads.Zg;
import java.util.concurrent.ScheduledExecutorService;

/* loaded from: classes2.dex */
public final class j implements CC {
    public final /* synthetic */ int a = 1;
    public final BC b;
    public final CC c;
    public final BC d;
    public final BC e;
    public final BC f;
    public final BC g;
    public final BC h;
    public final BC i;
    public final HC j;
    public final CC k;
    public final HC l;
    public final HC m;

    public j(C1741Ne c1741Ne, BC bc, BC bc2, BC bc3, BC bc4, BC bc5, BC bc6, BC bc7, BC bc8, BC bc9, H h, BC bc10) {
        this.k = c1741Ne;
        this.b = bc;
        this.d = bc2;
        this.e = bc3;
        this.f = bc4;
        this.g = bc5;
        this.h = bc6;
        this.i = bc7;
        this.l = bc8;
        this.j = bc9;
        this.c = h;
        this.m = bc10;
    }

    public androidx.camera.core.processing.e a() {
        Lq lq = (Lq) this.b.zzb();
        VersionInfoParcel versionInfoParcelB = ((C1741Ne) this.c).b();
        ApplicationInfo applicationInfo = (ApplicationInfo) this.d.zzb();
        String packageName = ((C1735Me) this.j).b.a().getPackageName();
        AbstractC1981ds.s(packageName);
        C2601s7 c2601s7 = AbstractC2773w7.a;
        return new androidx.camera.core.processing.e(lq, versionInfoParcelB, applicationInfo, packageName, com.google.android.gms.ads.internal.client.r.d.a.h(), (PackageInfo) this.e.zzb(), BC.a(this.f), ((C1729Le) this.k).a(), (String) this.g.zzb(), ((C1760Qf) this.l).b(), ((Tg) this.m).a(), (Vh) this.h.zzb(), ((Integer) this.i.zzb()).intValue());
    }

    public C2280kn b() {
        Context contextA = ((C1741Ne) this.k).a();
        Lq lq = (Lq) this.b.zzb();
        C2195in c2195in = (C2195in) this.d.zzb();
        Zg zg = (Zg) this.e.zzb();
        C2542qr c2542qr = (C2542qr) this.f.zzb();
        C2584rr c2584rr = (C2584rr) this.g.zzb();
        InterfaceC2488pg interfaceC2488pg = (InterfaceC2488pg) this.h.zzb();
        C2227jd c2227jd = AbstractC2270kd.a;
        AbstractC1981ds.s(c2227jd);
        return new C2280kn(contextA, lq, c2195in, zg, c2542qr, c2584rr, interfaceC2488pg, c2227jd, (ScheduledExecutorService) this.i.zzb(), (C2923zm) ((BC) this.l).zzb(), (Tq) ((BC) this.j).zzb(), ((H) this.c).a(), (Ek) ((BC) this.m).zzb());
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                C1765Re c1765Re = (C1765Re) ((DC) this.j).a;
                Context contextA = ((C1741Ne) this.k).a();
                P4 p4 = (P4) this.b.zzb();
                C2412nq c2412nq = (C2412nq) this.d.zzb();
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                return new i(c1765Re, contextA, p4, c2412nq, c2227jd, (ScheduledExecutorService) this.e.zzb(), (Kk) this.f.zzb(), (C2584rr) this.g.zzb(), ((C1741Ne) this.c).b(), ((H) this.m).b(), (C2067fq) this.h.zzb(), (A) this.i.zzb(), (v) ((BC) this.l).zzb());
            case 1:
                return a();
            default:
                return b();
        }
    }

    public j(BC bc, C1741Ne c1741Ne, BC bc2, C1735Me c1735Me, BC bc3, BC bc4, C1729Le c1729Le, BC bc5, C1760Qf c1760Qf, Tg tg, BC bc6, BC bc7) {
        this.b = bc;
        this.c = c1741Ne;
        this.d = bc2;
        this.j = c1735Me;
        this.e = bc3;
        this.f = bc4;
        this.k = c1729Le;
        this.g = bc5;
        this.l = c1760Qf;
        this.m = tg;
        this.h = bc6;
        this.i = bc7;
    }

    public j(DC dc, C1741Ne c1741Ne, BC bc, BC bc2, BC bc3, BC bc4, BC bc5, C1741Ne c1741Ne2, H h, BC bc6, BC bc7, BC bc8) {
        this.j = dc;
        this.k = c1741Ne;
        this.b = bc;
        this.d = bc2;
        this.e = bc3;
        this.f = bc4;
        this.g = bc5;
        this.c = c1741Ne2;
        this.m = h;
        this.h = bc6;
        this.i = bc7;
        this.l = bc8;
    }
}
