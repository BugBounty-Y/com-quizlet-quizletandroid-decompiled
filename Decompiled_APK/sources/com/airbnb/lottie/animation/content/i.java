package com.airbnb.lottie.animation.content;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.LinearGradient;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.PointF;
import android.graphics.RadialGradient;
import android.graphics.RectF;
import android.graphics.Shader;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.collection.C0219q;
import com.airbnb.lottie.u;
import com.airbnb.lottie.y;

/* loaded from: classes.dex */
public final class i extends b {
    public com.airbnb.lottie.animation.keyframe.r A;
    public final String q;
    public final boolean r;
    public final C0219q s;
    public final C0219q t;
    public final RectF u;
    public final int v;
    public final int w;
    public final com.airbnb.lottie.animation.keyframe.j x;
    public final com.airbnb.lottie.animation.keyframe.j y;
    public final com.airbnb.lottie.animation.keyframe.j z;

    /* JADX WARN: Illegal instructions before constructor call */
    public i(u uVar, com.airbnb.lottie.model.layer.b bVar, com.airbnb.lottie.model.content.e eVar) {
        Paint.Join join;
        Paint.Join join2;
        int iK = AbstractC0147y.k(eVar.h);
        Paint.Cap cap = iK != 0 ? iK != 1 ? Paint.Cap.SQUARE : Paint.Cap.ROUND : Paint.Cap.BUTT;
        int iK2 = AbstractC0147y.k(eVar.i);
        if (iK2 == 0) {
            join = Paint.Join.MITER;
        } else if (iK2 == 1) {
            join = Paint.Join.ROUND;
        } else {
            if (iK2 != 2) {
                join2 = null;
                super(uVar, bVar, cap, join2, eVar.j, eVar.d, eVar.g, eVar.k, eVar.l);
                this.s = new C0219q((Object) null);
                this.t = new C0219q((Object) null);
                this.u = new RectF();
                this.q = eVar.a;
                this.v = eVar.b;
                this.r = eVar.m;
                this.w = (int) (uVar.a.b() / 32.0f);
                com.airbnb.lottie.animation.keyframe.e eVarJ = eVar.c.j();
                this.x = (com.airbnb.lottie.animation.keyframe.j) eVarJ;
                eVarJ.a(this);
                bVar.g(eVarJ);
                com.airbnb.lottie.animation.keyframe.e eVarJ2 = eVar.e.j();
                this.y = (com.airbnb.lottie.animation.keyframe.j) eVarJ2;
                eVarJ2.a(this);
                bVar.g(eVarJ2);
                com.airbnb.lottie.animation.keyframe.e eVarJ3 = eVar.f.j();
                this.z = (com.airbnb.lottie.animation.keyframe.j) eVarJ3;
                eVarJ3.a(this);
                bVar.g(eVarJ3);
            }
            join = Paint.Join.BEVEL;
        }
        join2 = join;
        super(uVar, bVar, cap, join2, eVar.j, eVar.d, eVar.g, eVar.k, eVar.l);
        this.s = new C0219q((Object) null);
        this.t = new C0219q((Object) null);
        this.u = new RectF();
        this.q = eVar.a;
        this.v = eVar.b;
        this.r = eVar.m;
        this.w = (int) (uVar.a.b() / 32.0f);
        com.airbnb.lottie.animation.keyframe.e eVarJ4 = eVar.c.j();
        this.x = (com.airbnb.lottie.animation.keyframe.j) eVarJ4;
        eVarJ4.a(this);
        bVar.g(eVarJ4);
        com.airbnb.lottie.animation.keyframe.e eVarJ22 = eVar.e.j();
        this.y = (com.airbnb.lottie.animation.keyframe.j) eVarJ22;
        eVarJ22.a(this);
        bVar.g(eVarJ22);
        com.airbnb.lottie.animation.keyframe.e eVarJ32 = eVar.f.j();
        this.z = (com.airbnb.lottie.animation.keyframe.j) eVarJ32;
        eVarJ32.a(this);
        bVar.g(eVarJ32);
    }

    @Override // com.airbnb.lottie.animation.content.b, com.airbnb.lottie.animation.content.e
    public final void c(Canvas canvas, Matrix matrix, int i, com.airbnb.lottie.utils.a aVar) {
        Shader shader;
        Shader radialGradient;
        if (this.r) {
            return;
        }
        f(this.u, matrix, false);
        int i2 = this.v;
        com.airbnb.lottie.animation.keyframe.j jVar = this.x;
        com.airbnb.lottie.animation.keyframe.j jVar2 = this.z;
        com.airbnb.lottie.animation.keyframe.j jVar3 = this.y;
        if (i2 == 1) {
            long jI = i();
            C0219q c0219q = this.s;
            shader = (LinearGradient) c0219q.c(jI);
            if (shader == null) {
                PointF pointF = (PointF) jVar3.e();
                PointF pointF2 = (PointF) jVar2.e();
                com.airbnb.lottie.model.content.c cVar = (com.airbnb.lottie.model.content.c) jVar.e();
                radialGradient = new LinearGradient(pointF.x, pointF.y, pointF2.x, pointF2.y, g(cVar.b), cVar.a, Shader.TileMode.CLAMP);
                c0219q.g(jI, radialGradient);
                shader = radialGradient;
            }
        } else {
            long jI2 = i();
            C0219q c0219q2 = this.t;
            shader = (RadialGradient) c0219q2.c(jI2);
            if (shader == null) {
                PointF pointF3 = (PointF) jVar3.e();
                PointF pointF4 = (PointF) jVar2.e();
                com.airbnb.lottie.model.content.c cVar2 = (com.airbnb.lottie.model.content.c) jVar.e();
                int[] iArrG = g(cVar2.b);
                radialGradient = new RadialGradient(pointF3.x, pointF3.y, (float) Math.hypot(pointF4.x - r10, pointF4.y - r11), iArrG, cVar2.a, Shader.TileMode.CLAMP);
                c0219q2.g(jI2, radialGradient);
                shader = radialGradient;
            }
        }
        this.i.setShader(shader);
        super.c(canvas, matrix, i, aVar);
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.airbnb.lottie.animation.content.b, com.airbnb.lottie.model.f
    public final void d(ColorFilter colorFilter, com.quizlet.data.repository.widget.b bVar) {
        super.d(colorFilter, bVar);
        if (colorFilter == y.G) {
            com.airbnb.lottie.animation.keyframe.r rVar = this.A;
            com.airbnb.lottie.model.layer.b bVar2 = this.f;
            if (rVar != null) {
                bVar2.o(rVar);
            }
            com.airbnb.lottie.animation.keyframe.r rVar2 = new com.airbnb.lottie.animation.keyframe.r(bVar, null);
            this.A = rVar2;
            rVar2.a(this);
            bVar2.g(this.A);
        }
    }

    public final int[] g(int[] iArr) {
        com.airbnb.lottie.animation.keyframe.r rVar = this.A;
        if (rVar != null) {
            Integer[] numArr = (Integer[]) rVar.e();
            int i = 0;
            if (iArr.length == numArr.length) {
                while (i < iArr.length) {
                    iArr[i] = numArr[i].intValue();
                    i++;
                }
            } else {
                iArr = new int[numArr.length];
                while (i < numArr.length) {
                    iArr[i] = numArr[i].intValue();
                    i++;
                }
            }
        }
        return iArr;
    }

    @Override // com.airbnb.lottie.animation.content.c
    public final String getName() {
        return this.q;
    }

    public final int i() {
        float f = this.y.d;
        float f2 = this.w;
        int iRound = Math.round(f * f2);
        int iRound2 = Math.round(this.z.d * f2);
        int iRound3 = Math.round(this.x.d * f2);
        int i = iRound != 0 ? 527 * iRound : 17;
        if (iRound2 != 0) {
            i = i * 31 * iRound2;
        }
        return iRound3 != 0 ? i * 31 * iRound3 : i;
    }
}
