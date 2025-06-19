package com.google.android.gms.internal.ads;

import java.util.Arrays;

/* renamed from: com.google.android.gms.internal.ads.dG, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1963dG {
    public int a;
    public int b;
    public int c = 0;
    public ZF[] d = new ZF[100];

    public final synchronized void a(int i) {
        int i2 = this.a;
        this.a = i;
        if (i < i2) {
            b();
        }
    }

    public final synchronized void b() {
        int i = this.a;
        String str = Yo.a;
        int iMax = Math.max(0, ((i + 65535) / 65536) - this.b);
        int i2 = this.c;
        if (iMax >= i2) {
            return;
        }
        Arrays.fill(this.d, iMax, i2, (Object) null);
        this.c = iMax;
    }
}
