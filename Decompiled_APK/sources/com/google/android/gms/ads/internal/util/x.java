package com.google.android.gms.ads.internal.util;

import com.google.android.gms.internal.ads.C1741Ne;
import com.google.android.gms.internal.ads.CC;

/* loaded from: classes2.dex */
public final class x implements CC {
    public final /* synthetic */ int a;
    public final C1741Ne b;

    public /* synthetic */ x(C1741Ne c1741Ne, int i) {
        this.a = i;
        this.b = c1741Ne;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final /* bridge */ /* synthetic */ Object zzb() {
        switch (this.a) {
            case 0:
                return new w(this.b.a());
            default:
                return new com.google.android.gms.ads.nonagon.signalgeneration.u(this.b.a());
        }
    }
}
