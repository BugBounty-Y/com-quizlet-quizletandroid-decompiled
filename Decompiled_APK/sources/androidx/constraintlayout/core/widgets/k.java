package androidx.constraintlayout.core.widgets;

/* loaded from: classes.dex */
public abstract class k {
    public static final boolean[] a = new boolean[3];

    /* JADX WARN: Removed duplicated region for block: B:190:0x0295  */
    /* JADX WARN: Removed duplicated region for block: B:207:0x02df  */
    /* JADX WARN: Removed duplicated region for block: B:213:0x0309  */
    /* JADX WARN: Removed duplicated region for block: B:235:0x0373  */
    /* JADX WARN: Removed duplicated region for block: B:237:0x038d  */
    /* JADX WARN: Removed duplicated region for block: B:402:0x0685 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:410:0x06a1  */
    /* JADX WARN: Removed duplicated region for block: B:413:0x06ac  */
    /* JADX WARN: Removed duplicated region for block: B:414:0x06af  */
    /* JADX WARN: Removed duplicated region for block: B:417:0x06b5  */
    /* JADX WARN: Removed duplicated region for block: B:418:0x06b8  */
    /* JADX WARN: Removed duplicated region for block: B:420:0x06bc  */
    /* JADX WARN: Removed duplicated region for block: B:425:0x06cc  */
    /* JADX WARN: Removed duplicated region for block: B:427:0x06d0 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:437:0x06ec A[ADDED_TO_REGION, REMOVE, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:65:0x00f1  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x0111  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void a(androidx.constraintlayout.core.widgets.f r40, androidx.constraintlayout.core.c r41, java.util.ArrayList r42, int r43) {
        /*
            Method dump skipped, instructions count: 1787
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.widgets.k.a(androidx.constraintlayout.core.widgets.f, androidx.constraintlayout.core.c, java.util.ArrayList, int):void");
    }

    public static void b(f fVar, androidx.constraintlayout.core.c cVar, e eVar) {
        eVar.p = -1;
        eVar.q = -1;
        d dVar = fVar.V[0];
        d dVar2 = d.b;
        d dVar3 = d.d;
        if (dVar != dVar2 && eVar.V[0] == dVar3) {
            c cVar2 = eVar.K;
            int i = cVar2.g;
            int iR = fVar.r();
            c cVar3 = eVar.M;
            int i2 = iR - cVar3.g;
            cVar2.i = cVar.k(cVar2);
            cVar3.i = cVar.k(cVar3);
            cVar.d(cVar2.i, i);
            cVar.d(cVar3.i, i2);
            eVar.p = 2;
            eVar.b0 = i;
            int i3 = i2 - i;
            eVar.X = i3;
            int i4 = eVar.e0;
            if (i3 < i4) {
                eVar.X = i4;
            }
        }
        if (fVar.V[1] == dVar2 || eVar.V[1] != dVar3) {
            return;
        }
        c cVar4 = eVar.L;
        int i5 = cVar4.g;
        int iL = fVar.l();
        c cVar5 = eVar.N;
        int i6 = iL - cVar5.g;
        cVar4.i = cVar.k(cVar4);
        cVar5.i = cVar.k(cVar5);
        cVar.d(cVar4.i, i5);
        cVar.d(cVar5.i, i6);
        if (eVar.d0 > 0 || eVar.j0 == 8) {
            c cVar6 = eVar.O;
            cVar6.i = cVar.k(cVar6);
            cVar.d(cVar6.i, eVar.d0 + i5);
        }
        eVar.q = 2;
        eVar.c0 = i5;
        int i7 = i6 - i5;
        eVar.Y = i7;
        int i8 = eVar.f0;
        if (i7 < i8) {
            eVar.Y = i8;
        }
    }

    public static final boolean c(int i, int i2) {
        return (i & i2) == i2;
    }
}
