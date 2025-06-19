package com.airbnb.lottie.parser;

import android.graphics.PointF;
import java.util.ArrayList;
import java.util.Collections;

/* loaded from: classes.dex */
public final class y implements E {
    public static final y a = new y();
    public static final com.airbnb.lottie.parser.moshi.c b = com.airbnb.lottie.parser.moshi.c.a("c", "v", "i", "o");

    @Override // com.airbnb.lottie.parser.E
    public final Object a(com.airbnb.lottie.parser.moshi.d dVar, float f) {
        if (dVar.B() == 1) {
            dVar.a();
        }
        dVar.d();
        ArrayList arrayListC = null;
        ArrayList arrayListC2 = null;
        ArrayList arrayListC3 = null;
        boolean zP = false;
        while (dVar.l()) {
            int iD = dVar.D(b);
            if (iD == 0) {
                zP = dVar.p();
            } else if (iD == 1) {
                arrayListC = o.c(dVar, f);
            } else if (iD == 2) {
                arrayListC2 = o.c(dVar, f);
            } else if (iD != 3) {
                dVar.P();
                dVar.Q();
            } else {
                arrayListC3 = o.c(dVar, f);
            }
        }
        dVar.i();
        if (dVar.B() == 2) {
            dVar.f();
        }
        if (arrayListC == null || arrayListC2 == null || arrayListC3 == null) {
            throw new IllegalArgumentException("Shape data was missing information.");
        }
        if (arrayListC.isEmpty()) {
            return new com.airbnb.lottie.model.content.k(new PointF(), false, Collections.EMPTY_LIST);
        }
        int size = arrayListC.size();
        PointF pointF = (PointF) arrayListC.get(0);
        ArrayList arrayList = new ArrayList(size);
        for (int i = 1; i < size; i++) {
            PointF pointF2 = (PointF) arrayListC.get(i);
            int i2 = i - 1;
            arrayList.add(new com.airbnb.lottie.model.a(com.airbnb.lottie.utils.g.a((PointF) arrayListC.get(i2), (PointF) arrayListC3.get(i2)), com.airbnb.lottie.utils.g.a(pointF2, (PointF) arrayListC2.get(i)), pointF2));
        }
        if (zP) {
            PointF pointF3 = (PointF) arrayListC.get(0);
            int i3 = size - 1;
            arrayList.add(new com.airbnb.lottie.model.a(com.airbnb.lottie.utils.g.a((PointF) arrayListC.get(i3), (PointF) arrayListC3.get(i3)), com.airbnb.lottie.utils.g.a(pointF3, (PointF) arrayListC2.get(0)), pointF3));
        }
        return new com.airbnb.lottie.model.content.k(pointF, zP, arrayList);
    }
}
