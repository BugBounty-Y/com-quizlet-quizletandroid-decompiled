package com.airbnb.lottie.model.layer;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PointF;
import android.graphics.RectF;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.collection.C0219q;
import com.airbnb.lottie.animation.keyframe.p;
import com.airbnb.lottie.animation.keyframe.r;
import com.airbnb.lottie.u;
import com.airbnb.lottie.y;
import com.google.android.gms.cloudmessaging.k;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/* loaded from: classes.dex */
public final class j extends b {
    public final StringBuilder D;
    public final RectF E;
    public final Matrix F;
    public final com.airbnb.lottie.animation.a G;
    public final com.airbnb.lottie.animation.a H;
    public final HashMap I;
    public final C0219q J;
    public final ArrayList K;
    public final com.airbnb.lottie.animation.keyframe.f L;
    public final u M;
    public final com.airbnb.lottie.h N;
    public final int O;
    public final com.airbnb.lottie.animation.keyframe.f P;
    public r Q;
    public final com.airbnb.lottie.animation.keyframe.f R;
    public r S;
    public final com.airbnb.lottie.animation.keyframe.i T;
    public r U;
    public final com.airbnb.lottie.animation.keyframe.i V;
    public r W;
    public final com.airbnb.lottie.animation.keyframe.f X;
    public r Y;
    public r Z;
    public final com.airbnb.lottie.animation.keyframe.f a0;
    public final com.airbnb.lottie.animation.keyframe.f b0;
    public final com.airbnb.lottie.animation.keyframe.f c0;

    public j(u uVar, e eVar) {
        k kVar;
        k kVar2;
        com.airbnb.lottie.model.animatable.a aVar;
        k kVar3;
        com.airbnb.lottie.model.animatable.a aVar2;
        k kVar4;
        com.airbnb.lottie.model.animatable.a aVar3;
        com.quizlet.data.repository.folderwithcreatorinclass.e eVar2;
        com.airbnb.lottie.model.animatable.a aVar4;
        com.quizlet.data.repository.folderwithcreatorinclass.e eVar3;
        com.airbnb.lottie.model.animatable.b bVar;
        com.quizlet.data.repository.folderwithcreatorinclass.e eVar4;
        com.airbnb.lottie.model.animatable.b bVar2;
        com.quizlet.data.repository.folderwithcreatorinclass.e eVar5;
        com.airbnb.lottie.model.animatable.a aVar5;
        com.quizlet.data.repository.folderwithcreatorinclass.e eVar6;
        com.airbnb.lottie.model.animatable.a aVar6;
        super(uVar, eVar);
        this.D = new StringBuilder(2);
        this.E = new RectF();
        this.F = new Matrix();
        com.airbnb.lottie.animation.a aVar7 = new com.airbnb.lottie.animation.a(1, 1);
        aVar7.setStyle(Paint.Style.FILL);
        this.G = aVar7;
        com.airbnb.lottie.animation.a aVar8 = new com.airbnb.lottie.animation.a(1, 2);
        aVar8.setStyle(Paint.Style.STROKE);
        this.H = aVar8;
        this.I = new HashMap();
        this.J = new C0219q((Object) null);
        this.K = new ArrayList();
        this.O = 2;
        this.M = uVar;
        this.N = eVar.b;
        com.airbnb.lottie.animation.keyframe.f fVar = new com.airbnb.lottie.animation.keyframe.f((List) eVar.q.b, 2);
        this.L = fVar;
        fVar.a(this);
        g(fVar);
        com.quizlet.data.repository.qclass.c cVar = eVar.r;
        if (cVar != null && (eVar6 = (com.quizlet.data.repository.folderwithcreatorinclass.e) cVar.b) != null && (aVar6 = (com.airbnb.lottie.model.animatable.a) eVar6.a) != null) {
            com.airbnb.lottie.animation.keyframe.e eVarJ = aVar6.j();
            this.P = (com.airbnb.lottie.animation.keyframe.f) eVarJ;
            eVarJ.a(this);
            g(eVarJ);
        }
        if (cVar != null && (eVar5 = (com.quizlet.data.repository.folderwithcreatorinclass.e) cVar.b) != null && (aVar5 = (com.airbnb.lottie.model.animatable.a) eVar5.b) != null) {
            com.airbnb.lottie.animation.keyframe.e eVarJ2 = aVar5.j();
            this.R = (com.airbnb.lottie.animation.keyframe.f) eVarJ2;
            eVarJ2.a(this);
            g(eVarJ2);
        }
        if (cVar != null && (eVar4 = (com.quizlet.data.repository.folderwithcreatorinclass.e) cVar.b) != null && (bVar2 = (com.airbnb.lottie.model.animatable.b) eVar4.c) != null) {
            com.airbnb.lottie.animation.keyframe.i iVarJ = bVar2.j();
            this.T = iVarJ;
            iVarJ.a(this);
            g(iVarJ);
        }
        if (cVar != null && (eVar3 = (com.quizlet.data.repository.folderwithcreatorinclass.e) cVar.b) != null && (bVar = (com.airbnb.lottie.model.animatable.b) eVar3.d) != null) {
            com.airbnb.lottie.animation.keyframe.i iVarJ2 = bVar.j();
            this.V = iVarJ2;
            iVarJ2.a(this);
            g(iVarJ2);
        }
        if (cVar != null && (eVar2 = (com.quizlet.data.repository.folderwithcreatorinclass.e) cVar.b) != null && (aVar4 = (com.airbnb.lottie.model.animatable.a) eVar2.e) != null) {
            com.airbnb.lottie.animation.keyframe.e eVarJ3 = aVar4.j();
            this.X = (com.airbnb.lottie.animation.keyframe.f) eVarJ3;
            eVarJ3.a(this);
            g(eVarJ3);
        }
        if (cVar != null && (kVar4 = (k) cVar.c) != null && (aVar3 = (com.airbnb.lottie.model.animatable.a) kVar4.c) != null) {
            com.airbnb.lottie.animation.keyframe.e eVarJ4 = aVar3.j();
            this.a0 = (com.airbnb.lottie.animation.keyframe.f) eVarJ4;
            eVarJ4.a(this);
            g(eVarJ4);
        }
        if (cVar != null && (kVar3 = (k) cVar.c) != null && (aVar2 = (com.airbnb.lottie.model.animatable.a) kVar3.d) != null) {
            com.airbnb.lottie.animation.keyframe.e eVarJ5 = aVar2.j();
            this.b0 = (com.airbnb.lottie.animation.keyframe.f) eVarJ5;
            eVarJ5.a(this);
            g(eVarJ5);
        }
        if (cVar != null && (kVar2 = (k) cVar.c) != null && (aVar = (com.airbnb.lottie.model.animatable.a) kVar2.e) != null) {
            com.airbnb.lottie.animation.keyframe.e eVarJ6 = aVar.j();
            this.c0 = (com.airbnb.lottie.animation.keyframe.f) eVarJ6;
            eVarJ6.a(this);
            g(eVarJ6);
        }
        if (cVar == null || (kVar = (k) cVar.c) == null) {
            return;
        }
        this.O = kVar.b;
    }

    public static void t(String str, Paint paint, Canvas canvas) {
        if (paint.getColor() == 0) {
            return;
        }
        if (paint.getStyle() == Paint.Style.STROKE && paint.getStrokeWidth() == DefinitionKt.NO_Float_VALUE) {
            return;
        }
        canvas.drawText(str, 0, str.length(), DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, paint);
    }

    public static void u(Path path, Paint paint, Canvas canvas) {
        if (paint.getColor() == 0) {
            return;
        }
        if (paint.getStyle() == Paint.Style.STROKE && paint.getStrokeWidth() == DefinitionKt.NO_Float_VALUE) {
            return;
        }
        canvas.drawPath(path, paint);
    }

    @Override // com.airbnb.lottie.model.layer.b, com.airbnb.lottie.model.f
    public final void d(ColorFilter colorFilter, com.quizlet.data.repository.widget.b bVar) {
        super.d(colorFilter, bVar);
        PointF pointF = y.a;
        if (colorFilter == 1) {
            r rVar = this.Q;
            if (rVar != null) {
                o(rVar);
            }
            r rVar2 = new r(bVar, null);
            this.Q = rVar2;
            rVar2.a(this);
            g(this.Q);
            return;
        }
        if (colorFilter == 2) {
            r rVar3 = this.S;
            if (rVar3 != null) {
                o(rVar3);
            }
            r rVar4 = new r(bVar, null);
            this.S = rVar4;
            rVar4.a(this);
            g(this.S);
            return;
        }
        if (colorFilter == y.n) {
            r rVar5 = this.U;
            if (rVar5 != null) {
                o(rVar5);
            }
            r rVar6 = new r(bVar, null);
            this.U = rVar6;
            rVar6.a(this);
            g(this.U);
            return;
        }
        if (colorFilter == y.o) {
            r rVar7 = this.W;
            if (rVar7 != null) {
                o(rVar7);
            }
            r rVar8 = new r(bVar, null);
            this.W = rVar8;
            rVar8.a(this);
            g(this.W);
            return;
        }
        if (colorFilter == y.A) {
            r rVar9 = this.Y;
            if (rVar9 != null) {
                o(rVar9);
            }
            r rVar10 = new r(bVar, null);
            this.Y = rVar10;
            rVar10.a(this);
            g(this.Y);
            return;
        }
        if (colorFilter != y.H) {
            if (colorFilter == y.J) {
                com.airbnb.lottie.animation.keyframe.f fVar = this.L;
                fVar.getClass();
                fVar.j(new p(new com.airbnb.lottie.value.b(), bVar, new com.airbnb.lottie.model.b()));
                return;
            }
            return;
        }
        r rVar11 = this.Z;
        if (rVar11 != null) {
            o(rVar11);
        }
        r rVar12 = new r(bVar, null);
        this.Z = rVar12;
        rVar12.a(this);
        g(this.Z);
    }

    @Override // com.airbnb.lottie.model.layer.b, com.airbnb.lottie.animation.content.e
    public final void f(RectF rectF, Matrix matrix, boolean z) {
        super.f(rectF, matrix, z);
        com.airbnb.lottie.h hVar = this.N;
        rectF.set(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, hVar.k.width(), hVar.k.height());
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:102:0x0338  */
    /* JADX WARN: Removed duplicated region for block: B:105:0x033e  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x03ba  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x00e5  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x02b7  */
    @Override // com.airbnb.lottie.model.layer.b
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void k(android.graphics.Canvas r30, android.graphics.Matrix r31, int r32, com.airbnb.lottie.utils.a r33) {
        /*
            Method dump skipped, instructions count: 1286
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.airbnb.lottie.model.layer.j.k(android.graphics.Canvas, android.graphics.Matrix, int, com.airbnb.lottie.utils.a):void");
    }

    public final void s(com.airbnb.lottie.model.b bVar, int i, int i2) {
        r rVar = this.Q;
        com.airbnb.lottie.animation.a aVar = this.G;
        if (rVar != null) {
            aVar.setColor(((Integer) rVar.e()).intValue());
        } else {
            com.airbnb.lottie.animation.keyframe.f fVar = this.P;
            if (fVar == null || !w(i2)) {
                aVar.setColor(bVar.h);
            } else {
                aVar.setColor(((Integer) fVar.e()).intValue());
            }
        }
        r rVar2 = this.S;
        com.airbnb.lottie.animation.a aVar2 = this.H;
        if (rVar2 != null) {
            aVar2.setColor(((Integer) rVar2.e()).intValue());
        } else {
            com.airbnb.lottie.animation.keyframe.f fVar2 = this.R;
            if (fVar2 == null || !w(i2)) {
                aVar2.setColor(bVar.i);
            } else {
                aVar2.setColor(((Integer) fVar2.e()).intValue());
            }
        }
        com.airbnb.lottie.animation.keyframe.e eVar = (com.airbnb.lottie.animation.keyframe.e) this.w.l;
        int iIntValue = 100;
        int iIntValue2 = eVar == null ? 100 : ((Integer) eVar.e()).intValue();
        com.airbnb.lottie.animation.keyframe.f fVar3 = this.X;
        if (fVar3 != null && w(i2)) {
            iIntValue = ((Integer) fVar3.e()).intValue();
        }
        int iRound = Math.round((((iIntValue / 100.0f) * ((iIntValue2 * 255.0f) / 100.0f)) * i) / 255.0f);
        aVar.setAlpha(iRound);
        aVar2.setAlpha(iRound);
        r rVar3 = this.U;
        if (rVar3 != null) {
            aVar2.setStrokeWidth(((Float) rVar3.e()).floatValue());
            return;
        }
        com.airbnb.lottie.animation.keyframe.i iVar = this.T;
        if (iVar == null || !w(i2)) {
            aVar2.setStrokeWidth(com.airbnb.lottie.utils.i.c() * bVar.j);
        } else {
            aVar2.setStrokeWidth(((Float) iVar.e()).floatValue());
        }
    }

    public final i v(int i) {
        ArrayList arrayList = this.K;
        for (int size = arrayList.size(); size < i; size++) {
            i iVar = new i();
            iVar.a = "";
            iVar.b = DefinitionKt.NO_Float_VALUE;
            arrayList.add(iVar);
        }
        return (i) arrayList.get(i - 1);
    }

    public final boolean w(int i) {
        com.airbnb.lottie.animation.keyframe.f fVar;
        int length = ((com.airbnb.lottie.model.b) this.L.e()).a.length();
        com.airbnb.lottie.animation.keyframe.f fVar2 = this.a0;
        if (fVar2 == null || (fVar = this.b0) == null) {
            return true;
        }
        int iMin = Math.min(((Integer) fVar2.e()).intValue(), ((Integer) fVar.e()).intValue());
        int iMax = Math.max(((Integer) fVar2.e()).intValue(), ((Integer) fVar.e()).intValue());
        com.airbnb.lottie.animation.keyframe.f fVar3 = this.c0;
        if (fVar3 != null) {
            int iIntValue = ((Integer) fVar3.e()).intValue();
            iMin += iIntValue;
            iMax += iIntValue;
        }
        if (this.O == 2) {
            return i >= iMin && i < iMax;
        }
        float f = (i / length) * 100.0f;
        return f >= ((float) iMin) && f < ((float) iMax);
    }

    public final boolean x(Canvas canvas, com.airbnb.lottie.model.b bVar, int i, float f) {
        PointF pointF = bVar.l;
        PointF pointF2 = bVar.m;
        float fC = com.airbnb.lottie.utils.i.c();
        float f2 = DefinitionKt.NO_Float_VALUE;
        float f3 = (i * bVar.f * fC) + (pointF == null ? 0.0f : (bVar.f * fC) + pointF.y);
        if (this.M.u && pointF2 != null && pointF != null && f3 >= pointF.y + pointF2.y + bVar.c) {
            return false;
        }
        float f4 = pointF == null ? 0.0f : pointF.x;
        if (pointF2 != null) {
            f2 = pointF2.x;
        }
        int iK = AbstractC0147y.k(bVar.d);
        if (iK == 0) {
            canvas.translate(f4, f3);
            return true;
        }
        if (iK == 1) {
            canvas.translate((f4 + f2) - f, f3);
            return true;
        }
        if (iK != 2) {
            return true;
        }
        canvas.translate(((f2 / 2.0f) + f4) - (f / 2.0f), f3);
        return true;
    }

    public final List y(String str, float f, com.airbnb.lottie.model.c cVar, float f2, float f3, boolean z) {
        float fMeasureText;
        int i = 0;
        int i2 = 0;
        boolean z2 = false;
        int i3 = 0;
        float f4 = 0.0f;
        float f5 = 0.0f;
        float f6 = 0.0f;
        for (int i4 = 0; i4 < str.length(); i4++) {
            char cCharAt = str.charAt(i4);
            if (z) {
                com.airbnb.lottie.model.d dVar = (com.airbnb.lottie.model.d) this.N.h.d(com.airbnb.lottie.model.d.a(cVar.a, cVar.c, cCharAt));
                if (dVar != null) {
                    fMeasureText = (com.airbnb.lottie.utils.i.c() * ((float) dVar.c) * f2) + f3;
                }
            } else {
                fMeasureText = this.G.measureText(str.substring(i4, i4 + 1)) + f3;
            }
            if (cCharAt == ' ') {
                z2 = true;
                f6 = fMeasureText;
            } else if (z2) {
                z2 = false;
                i3 = i4;
                f5 = fMeasureText;
            } else {
                f5 += fMeasureText;
            }
            f4 += fMeasureText;
            if (f > DefinitionKt.NO_Float_VALUE && f4 >= f && cCharAt != ' ') {
                i++;
                i iVarV = v(i);
                if (i3 == i2) {
                    iVarV.a = str.substring(i2, i4).trim();
                    iVarV.b = (f4 - fMeasureText) - ((r10.length() - r8.length()) * f6);
                    i2 = i4;
                    i3 = i2;
                    f4 = fMeasureText;
                    f5 = f4;
                } else {
                    iVarV.a = str.substring(i2, i3 - 1).trim();
                    iVarV.b = ((f4 - f5) - ((r8.length() - r14.length()) * f6)) - f6;
                    f4 = f5;
                    i2 = i3;
                }
            }
        }
        if (f4 > DefinitionKt.NO_Float_VALUE) {
            i++;
            i iVarV2 = v(i);
            iVarV2.a = str.substring(i2);
            iVarV2.b = f4;
        }
        return this.K.subList(0, i);
    }
}
