package com.airbnb.lottie.animation.content;

import android.graphics.BlurMaskFilter;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.LinearGradient;
import android.graphics.Matrix;
import android.graphics.Path;
import android.graphics.PointF;
import android.graphics.RadialGradient;
import android.graphics.RectF;
import android.graphics.Shader;
import androidx.collection.C0219q;
import com.airbnb.lottie.u;
import com.airbnb.lottie.y;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes.dex */
public final class h implements e, com.airbnb.lottie.animation.keyframe.a, k {
    public final String a;
    public final boolean b;
    public final com.airbnb.lottie.model.layer.b c;
    public final C0219q d = new C0219q((Object) null);
    public final C0219q e = new C0219q((Object) null);
    public final Path f;
    public final com.airbnb.lottie.animation.a g;
    public final RectF h;
    public final ArrayList i;
    public final int j;
    public final com.airbnb.lottie.animation.keyframe.j k;
    public final com.airbnb.lottie.animation.keyframe.f l;
    public final com.airbnb.lottie.animation.keyframe.j m;
    public final com.airbnb.lottie.animation.keyframe.j n;
    public com.airbnb.lottie.animation.keyframe.r o;
    public com.airbnb.lottie.animation.keyframe.r p;
    public final u q;
    public final int r;
    public com.airbnb.lottie.animation.keyframe.e s;
    public float t;

    public h(u uVar, com.airbnb.lottie.h hVar, com.airbnb.lottie.model.layer.b bVar, com.airbnb.lottie.model.content.d dVar) {
        Path path = new Path();
        this.f = path;
        this.g = new com.airbnb.lottie.animation.a(1, 0);
        this.h = new RectF();
        this.i = new ArrayList();
        this.t = DefinitionKt.NO_Float_VALUE;
        this.c = bVar;
        this.a = dVar.g;
        this.b = dVar.h;
        this.q = uVar;
        this.j = dVar.a;
        path.setFillType(dVar.b);
        this.r = (int) (hVar.b() / 32.0f);
        com.airbnb.lottie.animation.keyframe.e eVarJ = dVar.c.j();
        this.k = (com.airbnb.lottie.animation.keyframe.j) eVarJ;
        eVarJ.a(this);
        bVar.g(eVarJ);
        com.airbnb.lottie.animation.keyframe.e eVarJ2 = dVar.d.j();
        this.l = (com.airbnb.lottie.animation.keyframe.f) eVarJ2;
        eVarJ2.a(this);
        bVar.g(eVarJ2);
        com.airbnb.lottie.animation.keyframe.e eVarJ3 = dVar.e.j();
        this.m = (com.airbnb.lottie.animation.keyframe.j) eVarJ3;
        eVarJ3.a(this);
        bVar.g(eVarJ3);
        com.airbnb.lottie.animation.keyframe.e eVarJ4 = dVar.f.j();
        this.n = (com.airbnb.lottie.animation.keyframe.j) eVarJ4;
        eVarJ4.a(this);
        bVar.g(eVarJ4);
        if (bVar.l() != null) {
            com.airbnb.lottie.animation.keyframe.i iVarJ = ((com.airbnb.lottie.model.animatable.b) bVar.l().b).j();
            this.s = iVarJ;
            iVarJ.a(this);
            bVar.g(this.s);
        }
    }

    @Override // com.airbnb.lottie.animation.keyframe.a
    public final void a() {
        this.q.invalidateSelf();
    }

    @Override // com.airbnb.lottie.animation.content.c
    public final void b(List list, List list2) {
        for (int i = 0; i < list2.size(); i++) {
            c cVar = (c) list2.get(i);
            if (cVar instanceof m) {
                this.i.add((m) cVar);
            }
        }
    }

    @Override // com.airbnb.lottie.animation.content.e
    public final void c(Canvas canvas, Matrix matrix, int i, com.airbnb.lottie.utils.a aVar) {
        float[] fArr;
        int[] iArr;
        Shader radialGradient;
        float[] fArr2;
        int[] iArr2;
        if (this.b) {
            return;
        }
        Path path = this.f;
        path.reset();
        int i2 = 0;
        while (true) {
            ArrayList arrayList = this.i;
            if (i2 >= arrayList.size()) {
                break;
            }
            path.addPath(((m) arrayList.get(i2)).h(), matrix);
            i2++;
        }
        path.computeBounds(this.h, false);
        int i3 = this.j;
        com.airbnb.lottie.animation.keyframe.j jVar = this.k;
        com.airbnb.lottie.animation.keyframe.j jVar2 = this.n;
        com.airbnb.lottie.animation.keyframe.j jVar3 = this.m;
        if (i3 == 1) {
            long jI = i();
            C0219q c0219q = this.d;
            radialGradient = (LinearGradient) c0219q.c(jI);
            if (radialGradient == null) {
                PointF pointF = (PointF) jVar3.e();
                PointF pointF2 = (PointF) jVar2.e();
                com.airbnb.lottie.model.content.c cVar = (com.airbnb.lottie.model.content.c) jVar.e();
                int[] iArrG = g(cVar.b);
                if (iArrG.length < 2) {
                    int[] iArr3 = {iArrG[0], iArrG[0]};
                    fArr2 = new float[]{DefinitionKt.NO_Float_VALUE, 1.0f};
                    iArr2 = iArr3;
                } else {
                    fArr2 = cVar.a;
                    iArr2 = iArrG;
                }
                radialGradient = new LinearGradient(pointF.x, pointF.y, pointF2.x, pointF2.y, iArr2, fArr2, Shader.TileMode.CLAMP);
                c0219q.g(jI, radialGradient);
            }
        } else {
            long jI2 = i();
            C0219q c0219q2 = this.e;
            RadialGradient radialGradient2 = (RadialGradient) c0219q2.c(jI2);
            if (radialGradient2 != null) {
                radialGradient = radialGradient2;
            } else {
                PointF pointF3 = (PointF) jVar3.e();
                PointF pointF4 = (PointF) jVar2.e();
                com.airbnb.lottie.model.content.c cVar2 = (com.airbnb.lottie.model.content.c) jVar.e();
                int[] iArrG2 = g(cVar2.b);
                if (iArrG2.length < 2) {
                    int[] iArr4 = {iArrG2[0], iArrG2[0]};
                    fArr = new float[]{DefinitionKt.NO_Float_VALUE, 1.0f};
                    iArr = iArr4;
                } else {
                    fArr = cVar2.a;
                    iArr = iArrG2;
                }
                float[] fArr3 = fArr;
                float f = pointF3.x;
                float f2 = pointF3.y;
                float fHypot = (float) Math.hypot(pointF4.x - f, pointF4.y - f2);
                if (fHypot <= DefinitionKt.NO_Float_VALUE) {
                    fHypot = 0.001f;
                }
                radialGradient = new RadialGradient(f, f2, fHypot, iArr, fArr3, Shader.TileMode.CLAMP);
                c0219q2.g(jI2, radialGradient);
            }
        }
        radialGradient.setLocalMatrix(matrix);
        com.airbnb.lottie.animation.a aVar2 = this.g;
        aVar2.setShader(radialGradient);
        com.airbnb.lottie.animation.keyframe.r rVar = this.o;
        if (rVar != null) {
            aVar2.setColorFilter((ColorFilter) rVar.e());
        }
        com.airbnb.lottie.animation.keyframe.e eVar = this.s;
        if (eVar != null) {
            float fFloatValue = ((Float) eVar.e()).floatValue();
            if (fFloatValue == DefinitionKt.NO_Float_VALUE) {
                aVar2.setMaskFilter(null);
            } else if (fFloatValue != this.t) {
                aVar2.setMaskFilter(new BlurMaskFilter(fFloatValue, BlurMaskFilter.Blur.NORMAL));
            }
            this.t = fFloatValue;
        }
        float fIntValue = ((Integer) this.l.e()).intValue() / 100.0f;
        aVar2.setAlpha(com.airbnb.lottie.utils.g.c((int) (i * fIntValue)));
        if (aVar != null) {
            aVar.a((int) (fIntValue * 255.0f), aVar2);
        }
        canvas.drawPath(path, aVar2);
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.airbnb.lottie.model.f
    public final void d(ColorFilter colorFilter, com.quizlet.data.repository.widget.b bVar) {
        PointF pointF = y.a;
        if (colorFilter == 4) {
            this.l.j(bVar);
            return;
        }
        ColorFilter colorFilter2 = y.F;
        com.airbnb.lottie.model.layer.b bVar2 = this.c;
        if (colorFilter == colorFilter2) {
            com.airbnb.lottie.animation.keyframe.r rVar = this.o;
            if (rVar != null) {
                bVar2.o(rVar);
            }
            com.airbnb.lottie.animation.keyframe.r rVar2 = new com.airbnb.lottie.animation.keyframe.r(bVar, null);
            this.o = rVar2;
            rVar2.a(this);
            bVar2.g(this.o);
            return;
        }
        if (colorFilter == y.G) {
            com.airbnb.lottie.animation.keyframe.r rVar3 = this.p;
            if (rVar3 != null) {
                bVar2.o(rVar3);
            }
            this.d.b();
            this.e.b();
            com.airbnb.lottie.animation.keyframe.r rVar4 = new com.airbnb.lottie.animation.keyframe.r(bVar, null);
            this.p = rVar4;
            rVar4.a(this);
            bVar2.g(this.p);
            return;
        }
        if (colorFilter == y.e) {
            com.airbnb.lottie.animation.keyframe.e eVar = this.s;
            if (eVar != null) {
                eVar.j(bVar);
                return;
            }
            com.airbnb.lottie.animation.keyframe.r rVar5 = new com.airbnb.lottie.animation.keyframe.r(bVar, null);
            this.s = rVar5;
            rVar5.a(this);
            bVar2.g(this.s);
        }
    }

    @Override // com.airbnb.lottie.model.f
    public final void e(com.airbnb.lottie.model.e eVar, int i, ArrayList arrayList, com.airbnb.lottie.model.e eVar2) {
        com.airbnb.lottie.utils.g.g(eVar, i, arrayList, eVar2, this);
    }

    @Override // com.airbnb.lottie.animation.content.e
    public final void f(RectF rectF, Matrix matrix, boolean z) {
        Path path = this.f;
        path.reset();
        int i = 0;
        while (true) {
            ArrayList arrayList = this.i;
            if (i >= arrayList.size()) {
                path.computeBounds(rectF, false);
                rectF.set(rectF.left - 1.0f, rectF.top - 1.0f, rectF.right + 1.0f, rectF.bottom + 1.0f);
                return;
            } else {
                path.addPath(((m) arrayList.get(i)).h(), matrix);
                i++;
            }
        }
    }

    public final int[] g(int[] iArr) {
        com.airbnb.lottie.animation.keyframe.r rVar = this.p;
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
        return this.a;
    }

    public final int i() {
        float f = this.m.d;
        float f2 = this.r;
        int iRound = Math.round(f * f2);
        int iRound2 = Math.round(this.n.d * f2);
        int iRound3 = Math.round(this.k.d * f2);
        int i = iRound != 0 ? 527 * iRound : 17;
        if (iRound2 != 0) {
            i = i * 31 * iRound2;
        }
        return iRound3 != 0 ? i * 31 * iRound3 : i;
    }
}
