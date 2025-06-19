package com.airbnb.lottie.parser;

import android.graphics.Color;
import android.graphics.PointF;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;

/* loaded from: classes.dex */
public abstract class o {
    public static final com.airbnb.lottie.parser.moshi.c a = com.airbnb.lottie.parser.moshi.c.a("x", "y");

    public static int a(com.airbnb.lottie.parser.moshi.d dVar) {
        dVar.a();
        int iQ = (int) (dVar.q() * 255.0d);
        int iQ2 = (int) (dVar.q() * 255.0d);
        int iQ3 = (int) (dVar.q() * 255.0d);
        while (dVar.l()) {
            dVar.Q();
        }
        dVar.f();
        return Color.argb(255, iQ, iQ2, iQ3);
    }

    public static PointF b(com.airbnb.lottie.parser.moshi.d dVar, float f) {
        int iK = AbstractC0147y.k(dVar.B());
        if (iK == 0) {
            dVar.a();
            float fQ = (float) dVar.q();
            float fQ2 = (float) dVar.q();
            while (dVar.B() != 2) {
                dVar.Q();
            }
            dVar.f();
            return new PointF(fQ * f, fQ2 * f);
        }
        if (iK != 2) {
            if (iK != 6) {
                throw new IllegalArgumentException("Unknown point starts with ".concat(assistantMode.refactored.a.r(dVar.B())));
            }
            float fQ3 = (float) dVar.q();
            float fQ4 = (float) dVar.q();
            while (dVar.l()) {
                dVar.Q();
            }
            return new PointF(fQ3 * f, fQ4 * f);
        }
        dVar.d();
        float fD = DefinitionKt.NO_Float_VALUE;
        float fD2 = 0.0f;
        while (dVar.l()) {
            int iD = dVar.D(a);
            if (iD == 0) {
                fD = d(dVar);
            } else if (iD != 1) {
                dVar.P();
                dVar.Q();
            } else {
                fD2 = d(dVar);
            }
        }
        dVar.i();
        return new PointF(fD * f, fD2 * f);
    }

    public static ArrayList c(com.airbnb.lottie.parser.moshi.d dVar, float f) {
        ArrayList arrayList = new ArrayList();
        dVar.a();
        while (dVar.B() == 1) {
            dVar.a();
            arrayList.add(b(dVar, f));
            dVar.f();
        }
        dVar.f();
        return arrayList;
    }

    public static float d(com.airbnb.lottie.parser.moshi.d dVar) {
        int iB = dVar.B();
        int iK = AbstractC0147y.k(iB);
        if (iK != 0) {
            if (iK == 6) {
                return (float) dVar.q();
            }
            throw new IllegalArgumentException("Unknown value for token of type ".concat(assistantMode.refactored.a.r(iB)));
        }
        dVar.a();
        float fQ = (float) dVar.q();
        while (dVar.l()) {
            dVar.Q();
        }
        dVar.f();
        return fQ;
    }
}
