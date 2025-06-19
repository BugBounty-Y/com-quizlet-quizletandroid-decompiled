package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class Lw {
    public static final Lw c;
    public static final Lw d;
    public static final Lw e;
    public static final Lw f;
    public static final Lw g;
    public static final Lw h;
    public static final Lw i;
    public static final Lw j;
    public final /* synthetic */ int a;
    public final String b;

    static {
        int i2 = 0;
        c = new Lw("TINK", i2);
        d = new Lw("CRUNCHY", i2);
        e = new Lw("NO_PREFIX", i2);
        int i3 = 1;
        f = new Lw("TINK", i3);
        g = new Lw("NO_PREFIX", i3);
        int i4 = 2;
        h = new Lw("TINK", i4);
        i = new Lw("CRUNCHY", i4);
        j = new Lw("NO_PREFIX", i4);
    }

    public /* synthetic */ Lw(String str, int i2) {
        this.a = i2;
        this.b = str;
    }

    public String toString() {
        switch (this.a) {
            case 0:
                return this.b;
            case 1:
                return this.b;
            case 2:
                return this.b;
            default:
                return super.toString();
        }
    }
}
