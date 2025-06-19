package com.google.android.gms.internal.ads;

import android.content.Context;

/* loaded from: classes2.dex */
public final class Ex implements InterfaceC2589rw {
    public final Context a;
    public final C2338m1 b;

    public Ex(Context context) {
        C2338m1 c2338m1 = new C2338m1(5);
        this.a = context.getApplicationContext();
        this.b = c2338m1;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2589rw
    /* renamed from: zza */
    public final Fw mo22zza() {
        C2338m1 c2338m1 = this.b;
        return new Rx(this.a, new C2807wz(null, c2338m1.a, c2338m1.b, false, (Fp) c2338m1.c));
    }
}
