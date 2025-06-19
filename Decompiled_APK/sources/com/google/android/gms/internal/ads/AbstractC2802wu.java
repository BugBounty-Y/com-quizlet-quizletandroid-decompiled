package com.google.android.gms.internal.ads;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.ads.wu, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2802wu implements Fw {
    public final boolean a;
    public final ArrayList b = new ArrayList(1);
    public int c;
    public C2891yx d;

    public AbstractC2802wu(boolean z) {
        this.a = z;
    }

    public final void b() {
        C2891yx c2891yx = this.d;
        String str = Yo.a;
        for (int i = 0; i < this.c; i++) {
            ((FC) this.b.get(i)).c(c2891yx, this.a);
        }
        this.d = null;
    }

    public final void e(int i) {
        C2891yx c2891yx = this.d;
        String str = Yo.a;
        for (int i2 = 0; i2 < this.c; i2++) {
            ((FC) this.b.get(i2)).f(c2891yx, this.a, i);
        }
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final void m(FC fc) {
        fc.getClass();
        ArrayList arrayList = this.b;
        if (arrayList.contains(fc)) {
            return;
        }
        arrayList.add(fc);
        this.c++;
    }

    public final void n(C2891yx c2891yx) {
        for (int i = 0; i < this.c; i++) {
            ((FC) this.b.get(i)).getClass();
        }
    }

    public final void p(C2891yx c2891yx) {
        this.d = c2891yx;
        for (int i = 0; i < this.c; i++) {
            ((FC) this.b.get(i)).b(this, c2891yx, this.a);
        }
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public /* synthetic */ Map zze() {
        return Collections.EMPTY_MAP;
    }
}
