package com.airbnb.lottie.parser;

import android.graphics.PointF;
import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes.dex */
public final class h implements E {
    public static final h a = new h();
    public static final com.airbnb.lottie.parser.moshi.c b = com.airbnb.lottie.parser.moshi.c.a("t", "f", "s", "j", "tr", "lh", "ls", "fc", "sc", "sw", "of", "ps", "sz");

    @Override // com.airbnb.lottie.parser.E
    public final Object a(com.airbnb.lottie.parser.moshi.d dVar, float f) {
        String str;
        dVar.d();
        String strY = null;
        float fQ = 0.0f;
        float fQ2 = 0.0f;
        float fQ3 = 0.0f;
        float fQ4 = 0.0f;
        int iR = 0;
        int iA = 0;
        int iA2 = 0;
        boolean zP = true;
        int i = 3;
        String strY2 = null;
        PointF pointF = null;
        PointF pointF2 = null;
        while (dVar.l()) {
            switch (dVar.D(b)) {
                case 0:
                    strY = dVar.y();
                    continue;
                case 1:
                    str = strY;
                    strY2 = dVar.y();
                    break;
                case 2:
                    str = strY;
                    fQ = (float) dVar.q();
                    break;
                case 3:
                    str = strY;
                    int iR2 = dVar.r();
                    if (iR2 <= 2 && iR2 >= 0) {
                        i = AbstractC0147y.n(3)[iR2];
                        break;
                    } else {
                        i = 3;
                        break;
                    }
                case 4:
                    str = strY;
                    iR = dVar.r();
                    break;
                case 5:
                    str = strY;
                    fQ2 = (float) dVar.q();
                    break;
                case 6:
                    str = strY;
                    fQ3 = (float) dVar.q();
                    break;
                case 7:
                    str = strY;
                    iA = o.a(dVar);
                    break;
                case 8:
                    str = strY;
                    iA2 = o.a(dVar);
                    break;
                case 9:
                    str = strY;
                    fQ4 = (float) dVar.q();
                    break;
                case 10:
                    str = strY;
                    zP = dVar.p();
                    break;
                case 11:
                    str = strY;
                    dVar.a();
                    pointF = new PointF(((float) dVar.q()) * f, ((float) dVar.q()) * f);
                    dVar.f();
                    break;
                case 12:
                    dVar.a();
                    str = strY;
                    pointF2 = new PointF(((float) dVar.q()) * f, ((float) dVar.q()) * f);
                    dVar.f();
                    break;
                default:
                    dVar.P();
                    dVar.Q();
                    continue;
            }
            strY = str;
        }
        dVar.i();
        com.airbnb.lottie.model.b bVar = new com.airbnb.lottie.model.b();
        bVar.a = strY;
        bVar.b = strY2;
        bVar.c = fQ;
        bVar.d = i;
        bVar.e = iR;
        bVar.f = fQ2;
        bVar.g = fQ3;
        bVar.h = iA;
        bVar.i = iA2;
        bVar.j = fQ4;
        bVar.k = zP;
        bVar.l = pointF;
        bVar.m = pointF2;
        return bVar;
    }
}
