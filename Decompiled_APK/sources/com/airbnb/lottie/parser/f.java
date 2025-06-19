package com.airbnb.lottie.parser;

import android.graphics.Color;
import android.graphics.PointF;

/* loaded from: classes.dex */
public final class f implements E {
    public static final f b = new f(0);
    public static final f c = new f(1);
    public static final f d = new f(2);
    public static final f e = new f(3);
    public static final f f = new f(4);
    public static final f g = new f(5);
    public final /* synthetic */ int a;

    public /* synthetic */ f(int i) {
        this.a = i;
    }

    @Override // com.airbnb.lottie.parser.E
    public final Object a(com.airbnb.lottie.parser.moshi.d dVar, float f2) {
        switch (this.a) {
            case 0:
                boolean z = dVar.B() == 1;
                if (z) {
                    dVar.a();
                }
                double dQ = dVar.q();
                double dQ2 = dVar.q();
                double dQ3 = dVar.q();
                double dQ4 = dVar.B() == 7 ? dVar.q() : 1.0d;
                if (z) {
                    dVar.f();
                }
                if (dQ <= 1.0d && dQ2 <= 1.0d && dQ3 <= 1.0d) {
                    dQ *= 255.0d;
                    dQ2 *= 255.0d;
                    dQ3 *= 255.0d;
                    if (dQ4 <= 1.0d) {
                        dQ4 *= 255.0d;
                    }
                }
                return Integer.valueOf(Color.argb((int) dQ4, (int) dQ, (int) dQ2, (int) dQ3));
            case 1:
                return Float.valueOf(o.d(dVar) * f2);
            case 2:
                return Integer.valueOf(Math.round(o.d(dVar) * f2));
            case 3:
                return o.b(dVar, f2);
            case 4:
                int iB = dVar.B();
                if (iB != 1 && iB != 3) {
                    if (iB != 7) {
                        throw new IllegalArgumentException("Cannot convert json to point. Next token is ".concat(assistantMode.refactored.a.r(iB)));
                    }
                    PointF pointF = new PointF(((float) dVar.q()) * f2, ((float) dVar.q()) * f2);
                    while (dVar.l()) {
                        dVar.Q();
                    }
                    return pointF;
                }
                return o.b(dVar, f2);
            default:
                boolean z2 = dVar.B() == 1;
                if (z2) {
                    dVar.a();
                }
                float fQ = (float) dVar.q();
                float fQ2 = (float) dVar.q();
                while (dVar.l()) {
                    dVar.Q();
                }
                if (z2) {
                    dVar.f();
                }
                return new com.airbnb.lottie.value.c((fQ / 100.0f) * f2, (fQ2 / 100.0f) * f2);
        }
    }
}
