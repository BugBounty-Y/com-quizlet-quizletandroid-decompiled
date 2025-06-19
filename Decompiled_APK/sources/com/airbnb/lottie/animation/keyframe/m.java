package com.airbnb.lottie.animation.keyframe;

import android.graphics.Path;
import android.graphics.PathMeasure;
import android.graphics.PointF;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class m extends k {
    public final PointF i;
    public final float[] j;
    public final float[] k;
    public final PathMeasure l;
    public l m;

    public m(ArrayList arrayList) {
        super(arrayList);
        this.i = new PointF();
        this.j = new float[2];
        this.k = new float[2];
        this.l = new PathMeasure();
    }

    @Override // com.airbnb.lottie.animation.keyframe.e
    public final Object f(com.airbnb.lottie.value.a aVar, float f) {
        float f2;
        l lVar = (l) aVar;
        Path path = lVar.q;
        com.quizlet.data.repository.widget.b bVar = this.e;
        if (bVar == null || aVar.h == null) {
            f2 = f;
        } else {
            f2 = f;
            PointF pointF = (PointF) bVar.n(lVar.g, lVar.h.floatValue(), (PointF) lVar.b, (PointF) lVar.c, d(), f2, this.d);
            if (pointF != null) {
                return pointF;
            }
        }
        if (path == null) {
            return (PointF) aVar.b;
        }
        l lVar2 = this.m;
        PathMeasure pathMeasure = this.l;
        if (lVar2 != lVar) {
            pathMeasure.setPath(path, false);
            this.m = lVar;
        }
        float length = pathMeasure.getLength();
        float f3 = f2 * length;
        float[] fArr = this.j;
        float[] fArr2 = this.k;
        pathMeasure.getPosTan(f3, fArr, fArr2);
        PointF pointF2 = this.i;
        pointF2.set(fArr[0], fArr[1]);
        if (f3 < DefinitionKt.NO_Float_VALUE) {
            pointF2.offset(fArr2[0] * f3, fArr2[1] * f3);
            return pointF2;
        }
        if (f3 > length) {
            float f4 = f3 - length;
            pointF2.offset(fArr2[0] * f4, fArr2[1] * f4);
        }
        return pointF2;
    }
}
