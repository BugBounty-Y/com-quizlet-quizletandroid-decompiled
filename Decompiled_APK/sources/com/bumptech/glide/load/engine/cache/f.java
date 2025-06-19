package com.bumptech.glide.load.engine.cache;

import com.google.android.gms.ads.internal.client.zzr;

/* loaded from: classes.dex */
public final class f {
    public int a;
    public int b;
    public int c;

    public f() {
        this.a = 0;
        this.b = 0;
        this.c = 0;
    }

    public static f a(zzr zzrVar) {
        return zzrVar.d ? new f(3, 0, 0) : zzrVar.i ? new f(2, 0, 0) : zzrVar.h ? new f(0, 0, 0) : new f(1, zzrVar.f, zzrVar.c);
    }

    public boolean b() {
        return this.a == 3;
    }

    public f(int i, int i2, int i3) {
        this.a = i;
        this.c = i2;
        this.b = i3;
    }

    public /* synthetic */ f(boolean z, int i, int i2, int i3) {
        this.a = i;
        this.b = i2;
        this.c = i3;
    }
}
