package com.airbnb.lottie.parser;

import java.util.ArrayList;

/* loaded from: classes.dex */
public abstract class q {
    public static final com.airbnb.lottie.parser.moshi.c a = com.airbnb.lottie.parser.moshi.c.a("k");

    public static ArrayList a(com.airbnb.lottie.parser.moshi.d dVar, com.airbnb.lottie.h hVar, float f, E e, boolean z) {
        com.airbnb.lottie.parser.moshi.d dVar2;
        com.airbnb.lottie.h hVar2;
        float f2;
        E e2;
        boolean z2;
        ArrayList arrayList = new ArrayList();
        if (dVar.B() == 6) {
            hVar.a("Lottie doesn't support expressions.");
            return arrayList;
        }
        dVar.d();
        while (dVar.l()) {
            if (dVar.D(a) != 0) {
                dVar.Q();
            } else if (dVar.B() == 1) {
                dVar.a();
                if (dVar.B() == 7) {
                    com.airbnb.lottie.parser.moshi.d dVar3 = dVar;
                    com.airbnb.lottie.h hVar3 = hVar;
                    float f3 = f;
                    E e3 = e;
                    boolean z3 = z;
                    com.airbnb.lottie.value.a aVarB = p.b(dVar3, hVar3, f3, e3, false, z3);
                    dVar2 = dVar3;
                    hVar2 = hVar3;
                    f2 = f3;
                    e2 = e3;
                    z2 = z3;
                    arrayList.add(aVarB);
                } else {
                    dVar2 = dVar;
                    hVar2 = hVar;
                    f2 = f;
                    e2 = e;
                    z2 = z;
                    while (dVar2.l()) {
                        arrayList.add(p.b(dVar2, hVar2, f2, e2, true, z2));
                    }
                }
                dVar2.f();
                dVar = dVar2;
                hVar = hVar2;
                f = f2;
                e = e2;
                z = z2;
            } else {
                com.airbnb.lottie.parser.moshi.d dVar4 = dVar;
                arrayList.add(p.b(dVar4, hVar, f, e, false, z));
                dVar = dVar4;
            }
        }
        dVar.i();
        b(arrayList);
        return arrayList;
    }

    public static void b(ArrayList arrayList) {
        int i;
        Object obj;
        int size = arrayList.size();
        int i2 = 0;
        while (true) {
            i = size - 1;
            if (i2 >= i) {
                break;
            }
            com.airbnb.lottie.value.a aVar = (com.airbnb.lottie.value.a) arrayList.get(i2);
            i2++;
            com.airbnb.lottie.value.a aVar2 = (com.airbnb.lottie.value.a) arrayList.get(i2);
            aVar.h = Float.valueOf(aVar2.g);
            if (aVar.c == null && (obj = aVar2.b) != null) {
                aVar.c = obj;
                if (aVar instanceof com.airbnb.lottie.animation.keyframe.l) {
                    ((com.airbnb.lottie.animation.keyframe.l) aVar).d();
                }
            }
        }
        com.airbnb.lottie.value.a aVar3 = (com.airbnb.lottie.value.a) arrayList.get(i);
        if ((aVar3.b == null || aVar3.c == null) && arrayList.size() > 1) {
            arrayList.remove(aVar3);
        }
    }
}
