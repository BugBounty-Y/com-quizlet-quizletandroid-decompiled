package com.airbnb.lottie.animation.keyframe;

import android.graphics.Matrix;
import android.graphics.Path;
import android.graphics.PointF;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class l extends com.airbnb.lottie.value.a {
    public Path q;
    public final com.airbnb.lottie.value.a r;

    public l(com.airbnb.lottie.h hVar, com.airbnb.lottie.value.a aVar) {
        super(hVar, (PointF) aVar.b, (PointF) aVar.c, aVar.d, aVar.e, aVar.f, aVar.g, aVar.h);
        this.r = aVar;
        d();
    }

    public final void d() {
        Object obj;
        Object obj2 = this.c;
        Object obj3 = this.b;
        boolean z = (obj2 == null || obj3 == null || !((PointF) obj3).equals(((PointF) obj2).x, ((PointF) obj2).y)) ? false : true;
        if (obj3 == null || (obj = this.c) == null || z) {
            return;
        }
        PointF pointF = (PointF) obj3;
        PointF pointF2 = (PointF) obj;
        com.airbnb.lottie.value.a aVar = this.r;
        PointF pointF3 = aVar.o;
        PointF pointF4 = aVar.p;
        Matrix matrix = com.airbnb.lottie.utils.i.a;
        Path path = new Path();
        path.moveTo(pointF.x, pointF.y);
        if (pointF3 == null || pointF4 == null || (pointF3.length() == DefinitionKt.NO_Float_VALUE && pointF4.length() == DefinitionKt.NO_Float_VALUE)) {
            path.lineTo(pointF2.x, pointF2.y);
        } else {
            float f = pointF3.x + pointF.x;
            float f2 = pointF.y + pointF3.y;
            float f3 = pointF2.x;
            float f4 = f3 + pointF4.x;
            float f5 = pointF2.y;
            path.cubicTo(f, f2, f4, f5 + pointF4.y, f3, f5);
        }
        this.q = path;
    }
}
