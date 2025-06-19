package com.google.android.material.shape;

import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RadialGradient;
import android.graphics.RectF;
import android.graphics.Region;
import android.graphics.Shader;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public final class m extends r {
    public final o c;

    public m(o oVar) {
        this.c = oVar;
    }

    @Override // com.google.android.material.shape.r
    public final void a(Matrix matrix, com.google.android.material.shadow.a aVar, int i, Canvas canvas) {
        o oVar = this.c;
        float f = oVar.f;
        float f2 = oVar.g;
        RectF rectF = new RectF(oVar.b, oVar.c, oVar.d, oVar.e);
        aVar.getClass();
        boolean z = f2 < DefinitionKt.NO_Float_VALUE;
        Path path = aVar.g;
        int[] iArr = com.google.android.material.shadow.a.k;
        if (z) {
            iArr[0] = 0;
            iArr[1] = aVar.f;
            iArr[2] = aVar.e;
            iArr[3] = aVar.d;
        } else {
            path.rewind();
            path.moveTo(rectF.centerX(), rectF.centerY());
            path.arcTo(rectF, f, f2);
            path.close();
            float f3 = -i;
            rectF.inset(f3, f3);
            iArr[0] = 0;
            iArr[1] = aVar.d;
            iArr[2] = aVar.e;
            iArr[3] = aVar.f;
        }
        float fWidth = rectF.width() / 2.0f;
        if (fWidth <= DefinitionKt.NO_Float_VALUE) {
            return;
        }
        float f4 = 1.0f - (i / fWidth);
        float[] fArr = com.google.android.material.shadow.a.l;
        fArr[1] = f4;
        fArr[2] = ((1.0f - f4) / 2.0f) + f4;
        RadialGradient radialGradient = new RadialGradient(rectF.centerX(), rectF.centerY(), fWidth, iArr, fArr, Shader.TileMode.CLAMP);
        Paint paint = aVar.b;
        paint.setShader(radialGradient);
        canvas.save();
        canvas.concat(matrix);
        canvas.scale(1.0f, rectF.height() / rectF.width());
        if (!z) {
            canvas.clipPath(path, Region.Op.DIFFERENCE);
            canvas.drawPath(path, aVar.h);
        }
        canvas.drawArc(rectF, f, f2, true, paint);
        canvas.restore();
    }
}
