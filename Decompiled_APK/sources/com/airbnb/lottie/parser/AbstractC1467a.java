package com.airbnb.lottie.parser;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3526s;
import java.util.ArrayList;

/* renamed from: com.airbnb.lottie.parser.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1467a {
    public static final com.airbnb.lottie.parser.moshi.c a = com.airbnb.lottie.parser.moshi.c.a("k", "x", "y");

    public static com.airbnb.lottie.model.animatable.c a(com.airbnb.lottie.parser.moshi.e eVar, com.airbnb.lottie.h hVar) {
        ArrayList arrayList = new ArrayList();
        if (eVar.B() == 1) {
            eVar.a();
            while (eVar.l()) {
                com.airbnb.lottie.parser.moshi.e eVar2 = eVar;
                com.airbnb.lottie.h hVar2 = hVar;
                arrayList.add(new com.airbnb.lottie.animation.keyframe.l(hVar2, p.b(eVar2, hVar2, com.airbnb.lottie.utils.i.c(), f.e, eVar.B() == 3, false)));
                eVar = eVar2;
                hVar = hVar2;
            }
            eVar.f();
            q.b(arrayList);
        } else {
            arrayList.add(new com.airbnb.lottie.value.a(o.b(eVar, com.airbnb.lottie.utils.i.c())));
        }
        return new com.airbnb.lottie.model.animatable.c(arrayList);
    }

    public static com.airbnb.lottie.model.animatable.f b(com.airbnb.lottie.parser.moshi.e eVar, com.airbnb.lottie.h hVar) {
        eVar.d();
        com.airbnb.lottie.model.animatable.c cVarA = null;
        com.airbnb.lottie.model.animatable.b bVarB = null;
        boolean z = false;
        com.airbnb.lottie.model.animatable.b bVarB2 = null;
        while (eVar.B() != 4) {
            int iD = eVar.D(a);
            if (iD == 0) {
                cVarA = a(eVar, hVar);
            } else if (iD != 1) {
                if (iD != 2) {
                    eVar.P();
                    eVar.Q();
                } else if (eVar.B() == 6) {
                    eVar.Q();
                    z = true;
                } else {
                    bVarB = AbstractC3526s.b(eVar, hVar, true);
                }
            } else if (eVar.B() == 6) {
                eVar.Q();
                z = true;
            } else {
                bVarB2 = AbstractC3526s.b(eVar, hVar, true);
            }
        }
        eVar.i();
        if (z) {
            hVar.a("Lottie doesn't support expressions.");
        }
        return cVarA != null ? cVarA : new com.airbnb.lottie.model.animatable.d(bVarB2, bVarB);
    }
}
