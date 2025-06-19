package com.google.android.gms.internal.ads;

import android.util.Pair;

/* loaded from: classes2.dex */
public final /* synthetic */ class CD implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ DD b;
    public final /* synthetic */ Pair c;
    public final /* synthetic */ YE d;
    public final /* synthetic */ androidx.compose.animation.core.S0 e;

    public /* synthetic */ CD(DD dd, Pair pair, YE ye, androidx.compose.animation.core.S0 s0, int i) {
        this.a = i;
        this.b = dd;
        this.c = pair;
        this.d = ye;
        this.e = s0;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                WD wd = (WD) this.b.b.i;
                Pair pair = this.c;
                wd.e(((Integer) pair.first).intValue(), (C2093gF) pair.second, this.d, this.e);
                break;
            default:
                WD wd2 = (WD) this.b.b.i;
                Pair pair2 = this.c;
                wd2.c(((Integer) pair2.first).intValue(), (C2093gF) pair2.second, this.d, this.e);
                break;
        }
    }
}
