package com.airbnb.lottie.model.layer;

import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ColorFilter;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
import com.airbnb.lottie.animation.keyframe.r;
import com.airbnb.lottie.u;
import com.airbnb.lottie.y;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class h extends b {
    public final RectF D;
    public final com.airbnb.lottie.animation.a E;
    public final float[] F;
    public final Path G;
    public final e H;
    public r I;
    public r J;

    public h(u uVar, e eVar) {
        super(uVar, eVar);
        this.D = new RectF();
        com.airbnb.lottie.animation.a aVar = new com.airbnb.lottie.animation.a();
        this.E = aVar;
        this.F = new float[8];
        this.G = new Path();
        this.H = eVar;
        aVar.setAlpha(0);
        aVar.setStyle(Paint.Style.FILL);
        aVar.setColor(eVar.l);
    }

    @Override // com.airbnb.lottie.model.layer.b, com.airbnb.lottie.model.f
    public final void d(ColorFilter colorFilter, com.quizlet.data.repository.widget.b bVar) {
        super.d(colorFilter, bVar);
        if (colorFilter == y.F) {
            this.I = new r(bVar, null);
        } else if (colorFilter == 1) {
            this.J = new r(bVar, null);
        }
    }

    @Override // com.airbnb.lottie.model.layer.b, com.airbnb.lottie.animation.content.e
    public final void f(RectF rectF, Matrix matrix, boolean z) {
        super.f(rectF, matrix, z);
        RectF rectF2 = this.D;
        e eVar = this.H;
        rectF2.set(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, eVar.j, eVar.k);
        this.n.mapRect(rectF2);
        rectF.set(rectF2);
    }

    @Override // com.airbnb.lottie.model.layer.b
    public final void k(Canvas canvas, Matrix matrix, int i, com.airbnb.lottie.utils.a aVar) {
        e eVar = this.H;
        int iAlpha = Color.alpha(eVar.l);
        if (iAlpha == 0) {
            return;
        }
        r rVar = this.J;
        Integer num = rVar == null ? null : (Integer) rVar.e();
        com.airbnb.lottie.animation.a aVar2 = this.E;
        if (num != null) {
            aVar2.setColor(num.intValue());
        } else {
            aVar2.setColor(eVar.l);
        }
        int iIntValue = (int) ((((iAlpha / 255.0f) * (((com.airbnb.lottie.animation.keyframe.e) this.w.l) == null ? 100 : ((Integer) r2.e()).intValue())) / 100.0f) * (i / 255.0f) * 255.0f);
        aVar2.setAlpha(iIntValue);
        if (aVar == null || Color.alpha(aVar.d) <= 0) {
            aVar2.clearShadowLayer();
        } else {
            aVar2.setShadowLayer(Math.max(aVar.a, Float.MIN_VALUE), aVar.b, aVar.c, aVar.d);
        }
        r rVar2 = this.I;
        if (rVar2 != null) {
            aVar2.setColorFilter((ColorFilter) rVar2.e());
        }
        if (iIntValue > 0) {
            float[] fArr = this.F;
            fArr[0] = 0.0f;
            fArr[1] = 0.0f;
            float f = eVar.j;
            fArr[2] = f;
            fArr[3] = 0.0f;
            fArr[4] = f;
            float f2 = eVar.k;
            fArr[5] = f2;
            fArr[6] = 0.0f;
            fArr[7] = f2;
            matrix.mapPoints(fArr);
            Path path = this.G;
            path.reset();
            path.moveTo(fArr[0], fArr[1]);
            path.lineTo(fArr[2], fArr[3]);
            path.lineTo(fArr[4], fArr[5]);
            path.lineTo(fArr[6], fArr[7]);
            path.lineTo(fArr[0], fArr[1]);
            path.close();
            canvas.drawPath(path, aVar2);
        }
    }
}
