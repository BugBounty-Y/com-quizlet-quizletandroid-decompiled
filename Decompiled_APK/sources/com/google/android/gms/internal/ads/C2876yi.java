package com.google.android.gms.internal.ads;

import java.util.Set;
import java.util.concurrent.Executor;

/* renamed from: com.google.android.gms.internal.ads.yi, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2876yi implements CC {
    public final /* synthetic */ int a;
    public final Fi b;
    public final BC c;

    public /* synthetic */ C2876yi(Fi fi, BC bc, int i) {
        this.a = i;
        this.b = fi;
        this.c = bc;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                Set setR = this.b.r((Kg) this.c.zzb());
                AbstractC1981ds.s(setR);
                return setR;
            default:
                return new C2318li(new C1796Wf((InterfaceC2529qe) this.b.c, 1), (Executor) this.c.zzb());
        }
    }
}
