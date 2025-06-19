package com.airbnb.lottie.utils;

import android.graphics.Path;
import android.graphics.PointF;
import com.airbnb.lottie.model.content.k;
import java.util.ArrayList;

/* loaded from: classes.dex */
public abstract class g {
    public static final PointF a = new PointF();

    public static PointF a(PointF pointF, PointF pointF2) {
        return new PointF(pointF.x + pointF2.x, pointF.y + pointF2.y);
    }

    public static float b(float f, float f2, float f3) {
        return Math.max(f2, Math.min(f3, f));
    }

    public static int c(int i) {
        return Math.max(0, Math.min(255, i));
    }

    public static int d(float f, float f2) {
        int i = (int) f;
        int i2 = (int) f2;
        int i3 = i / i2;
        int i4 = i % i2;
        if (!((i ^ i2) >= 0) && i4 != 0) {
            i3--;
        }
        return i - (i2 * i3);
    }

    public static void e(k kVar, Path path) {
        Path path2;
        path.reset();
        PointF pointF = kVar.b;
        path.moveTo(pointF.x, pointF.y);
        PointF pointF2 = a;
        pointF2.set(pointF.x, pointF.y);
        int i = 0;
        while (true) {
            ArrayList arrayList = kVar.a;
            if (i >= arrayList.size()) {
                break;
            }
            com.airbnb.lottie.model.a aVar = (com.airbnb.lottie.model.a) arrayList.get(i);
            PointF pointF3 = aVar.a;
            boolean zEquals = pointF3.equals(pointF2);
            PointF pointF4 = aVar.b;
            PointF pointF5 = aVar.c;
            if (zEquals && pointF4.equals(pointF5)) {
                path.lineTo(pointF5.x, pointF5.y);
                path2 = path;
            } else {
                path2 = path;
                path2.cubicTo(pointF3.x, pointF3.y, pointF4.x, pointF4.y, pointF5.x, pointF5.y);
            }
            pointF2.set(pointF5.x, pointF5.y);
            i++;
            path = path2;
        }
        Path path3 = path;
        if (kVar.c) {
            path3.close();
        }
    }

    public static float f(float f, float f2, float f3) {
        return android.support.v4.media.session.a.a(f2, f, f3, f);
    }

    public static void g(com.airbnb.lottie.model.e eVar, int i, ArrayList arrayList, com.airbnb.lottie.model.e eVar2, com.airbnb.lottie.animation.content.k kVar) {
        if (eVar.a(i, kVar.getName())) {
            String name = kVar.getName();
            com.airbnb.lottie.model.e eVar3 = new com.airbnb.lottie.model.e(eVar2);
            eVar3.a.add(name);
            com.airbnb.lottie.model.e eVar4 = new com.airbnb.lottie.model.e(eVar3);
            eVar4.b = kVar;
            arrayList.add(eVar4);
        }
    }
}
