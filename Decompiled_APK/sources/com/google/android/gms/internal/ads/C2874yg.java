package com.google.android.gms.internal.ads;

import com.comscore.streaming.EventType;
import java.util.Collections;
import java.util.Set;

/* renamed from: com.google.android.gms.internal.ads.yg, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2874yg implements CC {
    public final /* synthetic */ int a;
    public final BC b;

    public /* synthetic */ C2874yg(BC bc, int i) {
        this.a = i;
        this.b = bc;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        BC bc = this.b;
        switch (this.a) {
            case 0:
                C2318li c2318li = new C2318li((Cg) bc.zzb(), AbstractC2270kd.g);
                int i = AbstractC2459ou.c;
                break;
            case 1:
                C2533qi c2533qi = (C2533qi) bc.zzb();
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                break;
            case 2:
                C1682Df c1682Df = (C1682Df) bc.zzb();
                C2227jd c2227jd2 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd2);
                break;
            case 3:
                C1682Df c1682Df2 = (C1682Df) bc.zzb();
                C2227jd c2227jd3 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd3);
                break;
            case 4:
                C1682Df c1682Df3 = (C1682Df) bc.zzb();
                C2227jd c2227jd4 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd4);
                break;
            case 5:
                C1682Df c1682Df4 = (C1682Df) bc.zzb();
                C2227jd c2227jd5 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd5);
                break;
            case 6:
                C1682Df c1682Df5 = (C1682Df) bc.zzb();
                C2227jd c2227jd6 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd6);
                break;
            case 7:
                C1682Df c1682Df6 = (C1682Df) bc.zzb();
                C2227jd c2227jd7 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd7);
                break;
            case 8:
                C1682Df c1682Df7 = (C1682Df) bc.zzb();
                C2227jd c2227jd8 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd8);
                break;
            case 9:
                Ak ak = (Ak) bc.zzb();
                C2227jd c2227jd9 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd9);
                break;
            case 11:
                Ak ak2 = (Ak) bc.zzb();
                C2227jd c2227jd10 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd10);
                break;
            case 12:
                Ag ag = (Ag) bc.zzb();
                C2227jd c2227jd11 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd11);
                C2318li c2318li2 = new C2318li(ag, c2227jd11);
                int i2 = AbstractC2459ou.c;
                break;
            case 13:
                Ak ak3 = (Ak) bc.zzb();
                C2227jd c2227jd12 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd12);
                break;
            case 14:
                Ak ak4 = (Ak) bc.zzb();
                C2227jd c2227jd13 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd13);
                break;
            case 15:
                Ak ak5 = (Ak) bc.zzb();
                C2227jd c2227jd14 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd14);
                break;
            case EventType.WINDOW_STATE /* 22 */:
                C2916zf c2916zf = (C2916zf) bc.zzb();
                C2227jd c2227jd15 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd15);
                break;
            case EventType.AUDIO /* 23 */:
                String str = ((C2917zg) bc.zzb()).b.e;
                AbstractC1981ds.s(str);
                break;
            case EventType.VIDEO /* 24 */:
                Set setSingleton = Collections.singleton(new C2318li((Kg) bc.zzb(), AbstractC2270kd.g));
                AbstractC1981ds.s(setSingleton);
                break;
            case 27:
                Set setSingleton2 = Collections.singleton(new C2318li((Kg) bc.zzb(), AbstractC2270kd.g));
                AbstractC1981ds.s(setSingleton2);
                break;
        }
        return new C2318li((Bi) bc.zzb(), AbstractC2270kd.f);
    }
}
