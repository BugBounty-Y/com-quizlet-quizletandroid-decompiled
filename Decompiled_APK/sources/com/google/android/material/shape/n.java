package com.google.android.material.shape;

import android.graphics.Canvas;
import android.graphics.LinearGradient;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Shader;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public final class n extends r {
    public final p c;
    public final float d;
    public final float e;

    public n(p pVar, float f, float f2) {
        this.c = pVar;
        this.d = f;
        this.e = f2;
    }

    @Override // com.google.android.material.shape.r
    public final void a(Matrix matrix, com.google.android.material.shadow.a aVar, int i, Canvas canvas) {
        p pVar = this.c;
        float f = pVar.c;
        float f2 = this.e;
        float f3 = pVar.b;
        float f4 = this.d;
        RectF rectF = new RectF(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, (float) Math.hypot(f - f2, f3 - f4), DefinitionKt.NO_Float_VALUE);
        Matrix matrix2 = this.a;
        matrix2.set(matrix);
        matrix2.preTranslate(f4, f2);
        matrix2.preRotate(b());
        aVar.getClass();
        rectF.bottom += i;
        rectF.offset(DefinitionKt.NO_Float_VALUE, -i);
        int[] iArr = com.google.android.material.shadow.a.i;
        iArr[0] = aVar.f;
        iArr[1] = aVar.e;
        iArr[2] = aVar.d;
        Paint paint = aVar.c;
        float f5 = rectF.left;
        paint.setShader(new LinearGradient(f5, rectF.top, f5, rectF.bottom, iArr, com.google.android.material.shadow.a.j, Shader.TileMode.CLAMP));
        canvas.save();
        canvas.concat(matrix2);
        canvas.drawRect(rectF, paint);
        canvas.restore();
    }

    public final float b() {
        p pVar = this.c;
        return (float) Math.toDegrees(Math.atan((pVar.c - this.e) / (pVar.b - this.d)));
    }
}
