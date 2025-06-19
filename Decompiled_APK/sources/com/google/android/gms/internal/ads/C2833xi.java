package com.google.android.gms.internal.ads;

import com.comscore.streaming.EventType;
import java.util.Collections;
import java.util.Set;

/* renamed from: com.google.android.gms.internal.ads.xi, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2833xi implements CC {
    public final /* synthetic */ int a;
    public final BC b;

    public /* synthetic */ C2833xi(BC bc, int i) {
        this.a = i;
        this.b = bc;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                return new C2318li((Bi) this.b.zzb(), AbstractC2270kd.f);
            case 1:
                return new C2318li((C2061fk) this.b.zzb(), AbstractC2270kd.g);
            case 2:
                Set setSingleton = Collections.singleton(new C2318li((Kg) this.b.zzb(), AbstractC2270kd.g));
                AbstractC1981ds.s(setSingleton);
                return setSingleton;
            case 3:
                Di di = (Di) this.b.zzb();
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                return new C2318li(di, c2227jd);
            case 4:
                Set setSingleton2 = Collections.singleton(new C2318li((Ci) this.b.zzb(), AbstractC2270kd.g));
                AbstractC1981ds.s(setSingleton2);
                return setSingleton2;
            case 5:
                return new C2318li((C2059fi) this.b.zzb(), AbstractC2270kd.g);
            case 6:
                return new Ci((C2403nh) this.b.zzb());
            case 7:
                Zi zi = (Zi) this.b.zzb();
                AbstractC1981ds.s(zi);
                return zi;
            case 8:
                Ki ki = (Ki) this.b.zzb();
                AbstractC1981ds.s(ki);
                return ki;
            case 9:
                return new C2318li((C2748vj) this.b.zzb(), AbstractC2270kd.a);
            case 10:
                Mn mn = (Mn) this.b.zzb();
                C2227jd c2227jd2 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd2);
                return new C2318li(mn, c2227jd2);
            case 11:
                return new C2276kj((Hk) this.b.zzb());
            case 12:
                C2791wj c2791wj = (C2791wj) this.b.zzb();
                AbstractC1981ds.s(c2791wj);
                return c2791wj;
            case 13:
                return new C2318li((C2059fi) this.b.zzb(), AbstractC2270kd.g);
            case 14:
                C2792wk c2792wk = (C2792wk) this.b.zzb();
                C2227jd c2227jd3 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd3);
                return new C2318li(c2792wk, c2227jd3);
            case 15:
                C2792wk c2792wk2 = (C2792wk) this.b.zzb();
                C2227jd c2227jd4 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd4);
                return new C2318li(c2792wk2, c2227jd4);
            case 16:
                C2792wk c2792wk3 = (C2792wk) this.b.zzb();
                C2227jd c2227jd5 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd5);
                return new C2318li(c2792wk3, c2227jd5);
            case 17:
                C2792wk c2792wk4 = (C2792wk) this.b.zzb();
                C2227jd c2227jd6 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd6);
                return new C2318li(c2792wk4, c2227jd6);
            case 18:
                C2792wk c2792wk5 = (C2792wk) this.b.zzb();
                C2227jd c2227jd7 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd7);
                return new C2318li(c2792wk5, c2227jd7);
            case 19:
                C2792wk c2792wk6 = (C2792wk) this.b.zzb();
                C2227jd c2227jd8 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd8);
                return new C2318li(c2792wk6, c2227jd8);
            case 20:
                Bk bk = (Bk) this.b.zzb();
                C2227jd c2227jd9 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd9);
                return new C2318li(bk, c2227jd9);
            case 21:
                Bk bk2 = (Bk) this.b.zzb();
                C2227jd c2227jd10 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd10);
                return new C2318li(bk2, c2227jd10);
            case EventType.WINDOW_STATE /* 22 */:
                Bk bk3 = (Bk) this.b.zzb();
                C2227jd c2227jd11 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd11);
                return new C2318li(bk3, c2227jd11);
            case EventType.AUDIO /* 23 */:
                Bk bk4 = (Bk) this.b.zzb();
                C2227jd c2227jd12 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd12);
                return new C2318li(bk4, c2227jd12);
            case EventType.VIDEO /* 24 */:
                Jk jk = (Jk) this.b.zzb();
                C2227jd c2227jd13 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd13);
                return new C2318li(jk, c2227jd13);
            case EventType.SUBS /* 25 */:
                Kk kk = (Kk) this.b.zzb();
                C2227jd c2227jd14 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd14);
                return new Hk(kk, c2227jd14);
            case EventType.CDN /* 26 */:
                return new Nk((com.google.android.gms.common.util.a) this.b.zzb());
            case 27:
                Qk qk = (Qk) this.b.zzb();
                C2227jd c2227jd15 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd15);
                Set setI = C2147hi.i(qk, c2227jd15);
                AbstractC1981ds.s(setI);
                return setI;
            case 28:
                Qk qk2 = (Qk) this.b.zzb();
                C2227jd c2227jd16 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd16);
                Set setI2 = C2147hi.i(qk2, c2227jd16);
                AbstractC1981ds.s(setI2);
                return setI2;
            default:
                Qk qk3 = (Qk) this.b.zzb();
                C2227jd c2227jd17 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd17);
                Set setI3 = C2147hi.i(qk3, c2227jd17);
                AbstractC1981ds.s(setI3);
                return setI3;
        }
    }
}
