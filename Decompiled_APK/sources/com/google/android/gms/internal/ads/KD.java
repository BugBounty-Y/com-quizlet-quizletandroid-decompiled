package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class KD extends WE {
    public final /* synthetic */ int c = 0;
    public final Object d;

    public KD(A9 a9) {
        super(a9);
        this.d = new C2518q9();
    }

    @Override // com.google.android.gms.internal.ads.WE, com.google.android.gms.internal.ads.A9
    public C2303l9 d(int i, C2303l9 c2303l9, boolean z) {
        switch (this.c) {
            case 0:
                A9 a9 = this.b;
                C2303l9 c2303l9D = a9.d(i, c2303l9, z);
                if (a9.e(c2303l9D.c, (C2518q9) this.d, 0L).b()) {
                    Integer num = c2303l9.a;
                    Object obj = c2303l9.b;
                    int i2 = c2303l9.c;
                    long j = c2303l9.d;
                    P5 p5 = P5.b;
                    c2303l9D.b(num, obj, i2, j, true);
                } else {
                    c2303l9D.e = true;
                }
                return c2303l9D;
            default:
                return super.d(i, c2303l9, z);
        }
    }

    @Override // com.google.android.gms.internal.ads.WE, com.google.android.gms.internal.ads.A9
    public C2518q9 e(int i, C2518q9 c2518q9, long j) {
        switch (this.c) {
            case 1:
                this.b.e(i, c2518q9, j);
                C2640t3 c2640t3 = (C2640t3) this.d;
                c2518q9.b = c2640t3;
                V1 v1 = c2640t3.b;
                return c2518q9;
            default:
                return super.e(i, c2518q9, j);
        }
    }

    public KD(A9 a9, C2640t3 c2640t3) {
        super(a9);
        this.d = c2640t3;
    }
}
