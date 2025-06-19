package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public abstract class TF {
    public final int a;
    public final J9 b;
    public final int c;
    public final C1832aG d;

    public TF(int i, J9 j9, int i2) {
        this.a = i;
        this.b = j9;
        this.c = i2;
        this.d = j9.d[i2];
    }

    public abstract int a();

    public abstract boolean b(TF tf);
}
