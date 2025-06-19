package com.google.common.cache;

import java.util.logging.Logger;

/* loaded from: classes2.dex */
public abstract /* synthetic */ class m {
    public static final int[] a = {1, 2, 3, 4, 5, 6, 7, 8};

    public static void a(J j, J j2) {
        j2.d(j.f());
        J jA = j.a();
        Logger logger = I.u;
        jA.k(j2);
        j2.n(jA);
        J j3 = j.j();
        j2.k(j3);
        j3.n(j2);
        r rVar = r.a;
        j.k(rVar);
        j.n(rVar);
    }

    public static J b(int i, s sVar, J j, J j2, Object obj) {
        return d(i, sVar, obj, j.p(), j2);
    }

    public static void c(J j, J j2) {
        j2.g(j.c());
        J jO = j.o();
        Logger logger = I.u;
        jO.l(j2);
        j2.m(jO);
        J jE = j.e();
        j2.l(jE);
        jE.m(j2);
        r rVar = r.a;
        j.l(rVar);
        j.m(rVar);
    }

    public static J d(int i, s sVar, Object obj, int i2, J j) {
        switch (i) {
            case 1:
                return new A(obj, i2, j);
            case 2:
                y yVar = new y(obj, i2, j, 0);
                yVar.f = Long.MAX_VALUE;
                Logger logger = I.u;
                r rVar = r.a;
                yVar.g = rVar;
                yVar.h = rVar;
                return yVar;
            case 3:
                y yVar2 = new y(obj, i2, j, 1);
                yVar2.f = Long.MAX_VALUE;
                Logger logger2 = I.u;
                r rVar2 = r.a;
                yVar2.g = rVar2;
                yVar2.h = rVar2;
                return yVar2;
            case 4:
                z zVar = new z(obj, i2, j);
                zVar.e = Long.MAX_VALUE;
                Logger logger3 = I.u;
                r rVar3 = r.a;
                zVar.f = rVar3;
                zVar.g = rVar3;
                zVar.h = Long.MAX_VALUE;
                zVar.i = rVar3;
                zVar.j = rVar3;
                return zVar;
            case 5:
                return new F(sVar.h, obj, i2, j);
            case 6:
                D d = new D(sVar.h, obj, i2, j, 0);
                d.e = Long.MAX_VALUE;
                Logger logger4 = I.u;
                r rVar4 = r.a;
                d.f = rVar4;
                d.g = rVar4;
                return d;
            case 7:
                D d2 = new D(sVar.h, obj, i2, j, 1);
                d2.e = Long.MAX_VALUE;
                Logger logger5 = I.u;
                r rVar5 = r.a;
                d2.f = rVar5;
                d2.g = rVar5;
                return d2;
            default:
                E e = new E(sVar.h, obj, i2, j);
                e.d = Long.MAX_VALUE;
                Logger logger6 = I.u;
                r rVar6 = r.a;
                e.e = rVar6;
                e.f = rVar6;
                e.g = Long.MAX_VALUE;
                e.h = rVar6;
                e.i = rVar6;
                return e;
        }
    }
}
