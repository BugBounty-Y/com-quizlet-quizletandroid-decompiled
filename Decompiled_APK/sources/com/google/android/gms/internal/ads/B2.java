package com.google.android.gms.internal.ads;

import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/* loaded from: classes2.dex */
public final /* synthetic */ class B2 implements Comparator {
    public final /* synthetic */ int a;

    public /* synthetic */ B2(int i) {
        this.a = i;
    }

    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                return Integer.compare(((C2) obj).a.b, ((C2) obj2).a.b);
            case 1:
                return Long.compare(((A2) obj).b, ((A2) obj2).b);
            case 2:
                return ((byte[]) obj).length - ((byte[]) obj2).length;
            case 3:
                R5 r5 = (R5) obj;
                R5 r52 = (R5) obj2;
                int i = r5.c - r52.c;
                return i != 0 ? i : Long.compare(r5.a, r52.a);
            case 4:
                O5 o5 = (O5) obj;
                O5 o52 = (O5) obj2;
                float f = o5.b;
                float f2 = o52.b;
                if (f < f2) {
                    return -1;
                }
                if (f <= f2) {
                    float f3 = o5.a;
                    float f4 = o52.a;
                    if (f3 < f4) {
                        return -1;
                    }
                    if (f3 <= f4) {
                        float f5 = (o5.d - f) * (o5.c - f3);
                        float f6 = (o52.d - f2) * (o52.c - f4);
                        if (f5 > f6) {
                            return -1;
                        }
                        if (f5 >= f6) {
                            return 0;
                        }
                    }
                }
                return 1;
            case 5:
                return ((C1832aG) obj2).i - ((C1832aG) obj).i;
            case 6:
                Integer num = (Integer) obj;
                Integer num2 = (Integer) obj2;
                if (num.intValue() == -1) {
                    return num2.intValue() == -1 ? 0 : -1;
                }
                if (num2.intValue() == -1) {
                    return 1;
                }
                return num.intValue() - num2.intValue();
            case 7:
                return Integer.compare(((MF) ((List) obj).get(0)).f, ((MF) ((List) obj2).get(0)).f);
            case 8:
                List list = (List) obj;
                List list2 = (List) obj2;
                return C1897bu.f(new B2(11).compare((UF) Collections.max(list, new B2(11)), (UF) Collections.max(list2, new B2(11)))).b(list.size(), list2.size()).c((UF) Collections.max(list, new B2(12)), (UF) Collections.max(list2, new B2(12)), new B2(12)).a();
            case 9:
                return ((LF) Collections.max((List) obj)).compareTo((LF) Collections.max((List) obj2));
            case 10:
                return ((RF) ((List) obj).get(0)).compareTo((RF) ((List) obj2).get(0));
            case 11:
                UF uf = (UF) obj;
                UF uf2 = (UF) obj2;
                AbstractC1983du abstractC1983duD = AbstractC1983du.a.d(uf.h, uf2.h);
                Integer numValueOf = Integer.valueOf(uf.m);
                Integer numValueOf2 = Integer.valueOf(uf2.m);
                C2931zu c2931zu = C2931zu.c;
                AbstractC1983du abstractC1983duC = abstractC1983duD.c(numValueOf, numValueOf2, c2931zu).b(uf.n, uf2.n).b(uf.o, uf2.o).d(uf.p, uf2.p).b(uf.q, uf2.q).d(uf.i, uf2.i).d(uf.e, uf2.e).d(uf.g, uf2.g).c(Integer.valueOf(uf.l), Integer.valueOf(uf2.l), c2931zu);
                boolean z = uf2.s;
                boolean z2 = uf.s;
                AbstractC1983du abstractC1983duD2 = abstractC1983duC.d(z2, z);
                boolean z3 = uf2.t;
                boolean z4 = uf.t;
                AbstractC1983du abstractC1983duD3 = abstractC1983duD2.d(z4, z3);
                if (z2 && z4) {
                    abstractC1983duD3 = abstractC1983duD3.b(uf.u, uf2.u);
                }
                return abstractC1983duD3.a();
            case 12:
                UF uf3 = (UF) obj;
                UF uf4 = (UF) obj2;
                boolean z5 = uf3.e;
                Comparator iu = VF.i;
                if (!z5 || !uf3.h) {
                    iu = new Iu();
                }
                uf3.f.getClass();
                return C1897bu.f(iu.compare(Integer.valueOf(uf3.k), Integer.valueOf(uf4.k))).c(Integer.valueOf(uf3.j), Integer.valueOf(uf4.j), iu).a();
            case 13:
                return ((C2138hG) obj).a - ((C2138hG) obj2).a;
            default:
                return Float.compare(((C2138hG) obj).c, ((C2138hG) obj2).c);
        }
    }
}
