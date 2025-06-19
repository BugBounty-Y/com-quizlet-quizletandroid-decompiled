package com.google.android.gms.internal.ads;

import android.os.Bundle;
import com.google.android.gms.ads.internal.client.C1614q;

/* loaded from: classes2.dex */
public final class Zo implements Uo {
    public final int a;
    public final int b;

    public Zo(int i, int i2) {
        this.a = i;
        this.b = i2;
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* synthetic */ void b(Object obj) {
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final void c(Object obj) {
        int i;
        Bundle bundle = ((Og) obj).a;
        int i2 = this.a;
        if (i2 == -1 || (i = this.b) == -1) {
            return;
        }
        bundle.putInt("sessions_without_flags", i2);
        bundle.putInt("crashes_without_flags", i);
        C1614q c1614q = C1614q.f;
        if (com.google.android.gms.ads.internal.client.r.d.c.j) {
            bundle.putBoolean("did_reset", true);
        }
    }
}
