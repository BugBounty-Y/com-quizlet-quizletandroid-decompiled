package com.google.android.gms.internal.ads;

import android.content.Context;
import com.comscore.streaming.EventType;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;

/* loaded from: classes2.dex */
public final class Ok implements CC {
    public final /* synthetic */ int a;
    public final BC b;

    public Ok(C2147hi c2147hi, BC bc) {
        this.a = 0;
        this.b = bc;
    }

    public Yn a() {
        C2227jd c2227jd = AbstractC2270kd.a;
        AbstractC1981ds.s(c2227jd);
        return new Yn(1, c2227jd, (C2010ed) this.b.zzb());
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        Object nu;
        BC bc = this.b;
        switch (this.a) {
            case 0:
                Qk qk = (Qk) bc.zzb();
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                Set setI = C2147hi.i(qk, c2227jd);
                AbstractC1981ds.s(setI);
                return setI;
            case 1:
                Qk qk2 = (Qk) bc.zzb();
                C2227jd c2227jd2 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd2);
                Set setI2 = C2147hi.i(qk2, c2227jd2);
                AbstractC1981ds.s(setI2);
                return setI2;
            case 2:
                Qk qk3 = (Qk) bc.zzb();
                C2227jd c2227jd3 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd3);
                Set setI3 = C2147hi.i(qk3, c2227jd3);
                AbstractC1981ds.s(setI3);
                return setI3;
            case 3:
                Qk qk4 = (Qk) bc.zzb();
                C2227jd c2227jd4 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd4);
                Set setI4 = C2147hi.i(qk4, c2227jd4);
                AbstractC1981ds.s(setI4);
                return setI4;
            case 4:
                Qk qk5 = (Qk) bc.zzb();
                C2227jd c2227jd5 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd5);
                Set setI5 = C2147hi.i(qk5, c2227jd5);
                AbstractC1981ds.s(setI5);
                return setI5;
            case 5:
                Qk qk6 = (Qk) bc.zzb();
                C2227jd c2227jd6 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd6);
                Set setI6 = C2147hi.i(qk6, c2227jd6);
                AbstractC1981ds.s(setI6);
                return setI6;
            case 6:
                C2150hl c2150hl = (C2150hl) bc.zzb();
                C2227jd c2227jd7 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd7);
                return new C2318li(c2150hl, c2227jd7);
            case 7:
                C2150hl c2150hl2 = (C2150hl) bc.zzb();
                C2227jd c2227jd8 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd8);
                return new C2318li(c2150hl2, c2227jd8);
            case 8:
                C2150hl c2150hl3 = (C2150hl) bc.zzb();
                C2227jd c2227jd9 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd9);
                return new C2318li(c2150hl3, c2227jd9);
            case 9:
                return new C2318li((C2836xl) bc.zzb(), AbstractC2270kd.g);
            case 10:
                return new C2318li((C2836xl) bc.zzb(), AbstractC2270kd.g);
            case 11:
                return new C2318li((C2836xl) bc.zzb(), AbstractC2270kd.g);
            case 12:
                Context context = (Context) bc.zzb();
                C2227jd c2227jd10 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd10);
                return new El(context, c2227jd10, 0);
            case 13:
                C1845am c1845am = (C1845am) bc.zzb();
                C2227jd c2227jd11 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd11);
                return new C2318li(c1845am, c2227jd11);
            case 14:
                C1845am c1845am2 = (C1845am) bc.zzb();
                C2227jd c2227jd12 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd12);
                return new C2318li(c1845am2, c2227jd12);
            case 15:
                return new An((C2663tk) bc.zzb());
            case 16:
                return new Ln((Hk) bc.zzb());
            case 17:
                return a();
            case 18:
                C2227jd c2227jd13 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd13);
                C2839xo c2839xo = new C2839xo(c2227jd13, 0);
                ScheduledExecutorService scheduledExecutorService = (ScheduledExecutorService) bc.zzb();
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.h4)).booleanValue()) {
                    Io io2 = new Io(c2839xo, ((Integer) r2.c.a(AbstractC2773w7.i4)).intValue(), scheduledExecutorService);
                    int i = AbstractC2459ou.c;
                    nu = new Nu(io2);
                } else {
                    int i2 = AbstractC2459ou.c;
                    nu = Hu.j;
                }
                AbstractC1981ds.s(nu);
                return nu;
            case 19:
                C2227jd c2227jd14 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd14);
                return new Io(new C2839xo(c2227jd14, 1), ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.jc)).intValue(), (ScheduledExecutorService) bc.zzb());
            case 20:
                C2227jd c2227jd15 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd15);
                return new Yn(5, c2227jd15, (C2493pl) bc.zzb());
            case 21:
                return new Un((Up) bc.zzb(), 4);
            case EventType.WINDOW_STATE /* 22 */:
                return new C2411np((C2498pq) bc.zzb());
            case EventType.AUDIO /* 23 */:
                return new Np((C2498pq) bc.zzb());
            case EventType.VIDEO /* 24 */:
                return new C2067fq((P4) bc.zzb());
            case EventType.SUBS /* 25 */:
                return new C2318li((C2455oq) bc.zzb(), AbstractC2270kd.g);
            case EventType.CDN /* 26 */:
                ScheduledExecutorService scheduledExecutorServiceUnconfigurableScheduledExecutorService = Executors.unconfigurableScheduledExecutorService(Executors.newScheduledThreadPool(1, (ThreadFactory) bc.zzb()));
                AbstractC1981ds.s(scheduledExecutorServiceUnconfigurableScheduledExecutorService);
                return scheduledExecutorServiceUnconfigurableScheduledExecutorService;
            case 27:
                return new Tq((Uq) bc.zzb());
            case 28:
                return new Tq((Uq) bc.zzb());
            default:
                return new C2499pr((C2107gm) bc.zzb());
        }
    }

    public /* synthetic */ Ok(BC bc, int i) {
        this.a = i;
        this.b = bc;
    }
}
