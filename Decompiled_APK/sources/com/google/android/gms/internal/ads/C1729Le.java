package com.google.android.gms.internal.ads;

import com.comscore.streaming.EventType;
import java.util.Collections;
import java.util.Set;

/* renamed from: com.google.android.gms.internal.ads.Le, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1729Le implements CC {
    public final /* synthetic */ int a;
    public final BC b;

    public /* synthetic */ C1729Le(BC bc, int i) {
        this.a = i;
        this.b = bc;
    }

    public com.google.android.gms.ads.internal.util.C a() {
        return ((C2010ed) this.b.zzb()).d();
    }

    public C2098gd b() {
        return ((C2010ed) this.b.zzb()).c;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        int i = 1;
        BC bc = this.b;
        switch (this.a) {
            case 2:
                C1975dl c1975dl = (C1975dl) bc.zzb();
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                Set setSingleton = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.G1)).booleanValue() ? Collections.singleton(new C2318li(c1975dl, c2227jd)) : Collections.EMPTY_SET;
                AbstractC1981ds.s(setSingleton);
                break;
            case 5:
                Zj zj = (Zj) bc.zzb();
                C2227jd c2227jd2 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd2);
                break;
            case 14:
                C2318li c2318li = new C2318li((C2145hg) bc.zzb(), AbstractC2270kd.g);
                int i2 = AbstractC2459ou.c;
                break;
            case 15:
                Set setSingleton2 = Collections.singleton(new C2318li((C2145hg) bc.zzb(), AbstractC2270kd.g));
                AbstractC1981ds.s(setSingleton2);
                break;
            case 18:
                Set setSingleton3 = Collections.singleton(new C2318li((C2145hg) bc.zzb(), AbstractC2270kd.g));
                AbstractC1981ds.s(setSingleton3);
                break;
            case 19:
                C2273kg c2273kg = (C2273kg) bc.zzb();
                C2227jd c2227jd3 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd3);
                break;
            case 21:
                Ah ah = (Ah) bc.zzb();
                C2227jd c2227jd4 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd4);
                break;
            case EventType.WINDOW_STATE /* 22 */:
                Ah ah2 = (Ah) bc.zzb();
                C2227jd c2227jd5 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd5);
                break;
        }
        return new C2318li((C2917zg) bc.zzb(), AbstractC2270kd.g);
    }

    public /* synthetic */ C1729Le(com.google.firebase.messaging.u uVar, BC bc, int i) {
        this.a = i;
        this.b = bc;
    }
}
