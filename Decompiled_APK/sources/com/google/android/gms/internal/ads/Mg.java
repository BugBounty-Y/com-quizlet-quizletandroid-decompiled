package com.google.android.gms.internal.ads;

import android.content.Context;
import java.util.HashSet;

/* loaded from: classes2.dex */
public final class Mg implements CC {
    public final /* synthetic */ int a;
    public final C2702ug b;
    public final BC c;

    public Mg(C2702ug c2702ug, BC bc) {
        this.a = 1;
        this.b = c2702ug;
        this.c = bc;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                return new Lg(this.b.a());
            case 1:
                return new C2533qi(this.b.a(), (C2584rr) this.c.zzb());
            case 2:
                return new C2361mi((Context) this.c.zzb(), new HashSet(), this.b.a());
            default:
                return new C2061fk((C2489ph) this.c.zzb(), this.b.a());
        }
    }

    public /* synthetic */ Mg(BC bc, C2702ug c2702ug, int i) {
        this.a = i;
        this.c = bc;
        this.b = c2702ug;
    }
}
