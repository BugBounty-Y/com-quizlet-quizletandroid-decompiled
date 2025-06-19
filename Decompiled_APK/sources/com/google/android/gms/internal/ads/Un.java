package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Bundle;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class Un implements Vo {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ Un(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final int zza() {
        switch (this.a) {
            case 0:
                return 2;
            case 1:
                return 8;
            case 2:
                return 58;
            case 3:
                return 15;
            case 4:
                return 25;
            case 5:
                return 30;
            default:
                return 49;
        }
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final com.google.common.util.concurrent.e zzb() {
        switch (this.a) {
            case 0:
                return AbstractC2025es.E(new Vn(androidx.core.content.c.a((Context) this.b, "com.google.android.gms.permission.AD_ID") == 0, 0));
            case 1:
                ArrayList arrayList = new ArrayList();
                Iterator it2 = ((Set) this.b).iterator();
                while (it2.hasNext()) {
                    arrayList.add((String) it2.next());
                }
                return AbstractC2025es.E(new C2109go(0, arrayList));
            case 2:
                return AbstractC2025es.E(new Vn(((C2023eq) this.b).p, 1));
            case 3:
                String str = null;
                C2754vp c2754vp = (C2754vp) this.b;
                if (c2754vp == null) {
                    return AbstractC2025es.E(new C1934co(str, 2));
                }
                String str2 = c2754vp.a;
                return com.google.android.gms.common.util.e.a(str2) ? AbstractC2025es.E(new C1934co(str, 2)) : AbstractC2025es.E(new C1934co(str2, 2));
            case 4:
                return AbstractC2025es.E(new Ho((Up) this.b, 0));
            case 5:
                return AbstractC2025es.E(new C2196io((Bundle) this.b, 2));
            default:
                return AbstractC2025es.L(AbstractC2025es.O(AbstractC2025es.E(new Bundle()), ((Long) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.l4)).longValue(), TimeUnit.MILLISECONDS, (ScheduledExecutorService) this.b), new C2853y1(13), AbstractC2270kd.a);
        }
    }
}
