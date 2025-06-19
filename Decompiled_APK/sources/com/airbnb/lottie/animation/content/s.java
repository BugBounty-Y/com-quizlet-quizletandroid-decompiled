package com.airbnb.lottie.animation.content;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.PointF;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.airbnb.lottie.u;
import com.airbnb.lottie.y;

/* loaded from: classes.dex */
public final class s extends b {
    public final com.airbnb.lottie.model.layer.b q;
    public final String r;
    public final boolean s;
    public final com.airbnb.lottie.animation.keyframe.f t;
    public com.airbnb.lottie.animation.keyframe.r u;

    /* JADX WARN: Illegal instructions before constructor call */
    public s(u uVar, com.airbnb.lottie.model.layer.b bVar, com.airbnb.lottie.model.content.o oVar) {
        int iK = AbstractC0147y.k(oVar.g);
        Paint.Cap cap = iK != 0 ? iK != 1 ? Paint.Cap.SQUARE : Paint.Cap.ROUND : Paint.Cap.BUTT;
        int iK2 = AbstractC0147y.k(oVar.h);
        super(uVar, bVar, cap, iK2 != 0 ? iK2 != 1 ? iK2 != 2 ? null : Paint.Join.BEVEL : Paint.Join.ROUND : Paint.Join.MITER, oVar.i, oVar.e, oVar.f, oVar.c, oVar.b);
        this.q = bVar;
        this.r = oVar.a;
        this.s = oVar.j;
        com.airbnb.lottie.animation.keyframe.e eVarJ = oVar.d.j();
        this.t = (com.airbnb.lottie.animation.keyframe.f) eVarJ;
        eVarJ.a(this);
        bVar.g(eVarJ);
    }

    @Override // com.airbnb.lottie.animation.content.b, com.airbnb.lottie.animation.content.e
    public final void c(Canvas canvas, Matrix matrix, int i, com.airbnb.lottie.utils.a aVar) {
        if (this.s) {
            return;
        }
        com.airbnb.lottie.animation.keyframe.f fVar = this.t;
        int iL = fVar.l(fVar.c.b(), fVar.c());
        com.airbnb.lottie.animation.a aVar2 = this.i;
        aVar2.setColor(iL);
        com.airbnb.lottie.animation.keyframe.r rVar = this.u;
        if (rVar != null) {
            aVar2.setColorFilter((ColorFilter) rVar.e());
        }
        super.c(canvas, matrix, i, aVar);
    }

    @Override // com.airbnb.lottie.animation.content.b, com.airbnb.lottie.model.f
    public final void d(ColorFilter colorFilter, com.quizlet.data.repository.widget.b bVar) {
        super.d(colorFilter, bVar);
        PointF pointF = y.a;
        com.airbnb.lottie.animation.keyframe.f fVar = this.t;
        if (colorFilter == 2) {
            fVar.j(bVar);
            return;
        }
        if (colorFilter == y.F) {
            com.airbnb.lottie.animation.keyframe.r rVar = this.u;
            com.airbnb.lottie.model.layer.b bVar2 = this.q;
            if (rVar != null) {
                bVar2.o(rVar);
            }
            com.airbnb.lottie.animation.keyframe.r rVar2 = new com.airbnb.lottie.animation.keyframe.r(bVar, null);
            this.u = rVar2;
            rVar2.a(this);
            bVar2.g(fVar);
        }
    }

    @Override // com.airbnb.lottie.animation.content.c
    public final String getName() {
        return this.r;
    }
}
