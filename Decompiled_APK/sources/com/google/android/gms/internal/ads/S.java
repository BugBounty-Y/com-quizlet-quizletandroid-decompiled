package com.google.android.gms.internal.ads;

import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class S implements X {
    public static final int[] c = {5, 4, 12, 8, 3, 10, 9, 11, 6, 2, 0, 1, 7, 16, 15, 14, 17, 18, 19, 20, 21};
    public static final C1732Mb d = new C1732Mb((Q) new C1(13));
    public static final C1732Mb e = new C1732Mb((Q) new C1(14));
    public Bu a;
    public final C1 b = new C1(21);

    /* JADX WARN: Removed duplicated region for block: B:114:0x01c7  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x020a  */
    @Override // com.google.android.gms.internal.ads.X
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final synchronized com.google.android.gms.internal.ads.U[] a(android.net.Uri r27, java.util.Map r28) {
        /*
            Method dump skipped, instructions count: 1186
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.S.a(android.net.Uri, java.util.Map):com.google.android.gms.internal.ads.U[]");
    }

    public final void b(int i, ArrayList arrayList) {
        C1 c1 = this.b;
        switch (i) {
            case 0:
                arrayList.add(new P1(1));
                break;
            case 1:
                arrayList.add(new P1(2));
                break;
            case 2:
                arrayList.add(new J2());
                break;
            case 3:
                arrayList.add(new C2551r0());
                break;
            case 4:
                U uG = d.g(0);
                if (uG == null) {
                    arrayList.add(new D0());
                    break;
                } else {
                    arrayList.add(uG);
                    break;
                }
            case 5:
                arrayList.add(new F0());
                break;
            case 6:
                arrayList.add(new C2295l1(new C2209j1(), 0, c1));
                break;
            case 7:
                arrayList.add(new C2467p1());
                break;
            case 8:
                arrayList.add(new B1(c1, 0, Bu.e));
                arrayList.add(new F1(c1, 0));
                break;
            case 9:
                arrayList.add(new P1(0));
                break;
            case 10:
                arrayList.add(new C1993e3());
                break;
            case 11:
                if (this.a == null) {
                    C2244ju c2244ju = AbstractC2330lu.b;
                    this.a = Bu.e;
                }
                arrayList.add(new C2125h3(c1, new Eo(), new C2881yn(this.a, 3)));
                break;
            case 12:
                C2383n3 c2383n3 = new C2383n3();
                c2383n3.c = 0;
                c2383n3.d = -1L;
                c2383n3.f = -1;
                c2383n3.g = -1L;
                arrayList.add(c2383n3);
                break;
            case 14:
                arrayList.add(new B0(2));
                break;
            case 15:
                U uG2 = e.g(new Object[0]);
                if (uG2 != null) {
                    arrayList.add(uG2);
                    break;
                }
                break;
            case 16:
                arrayList.add(new C2637t0(c1));
                break;
            case 17:
                arrayList.add(new B0(1));
                break;
            case 18:
                arrayList.add(new A0(2));
                break;
            case 19:
                arrayList.add(new B0(0));
                break;
            case 20:
                arrayList.add(new A0(1));
                break;
            case 21:
                arrayList.add(new A0(0));
                break;
        }
    }
}
