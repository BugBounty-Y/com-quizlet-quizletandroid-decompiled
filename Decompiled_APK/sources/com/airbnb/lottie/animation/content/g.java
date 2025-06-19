package com.airbnb.lottie.animation.content;

import android.graphics.BlurMaskFilter;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Matrix;
import android.graphics.Path;
import android.graphics.PointF;
import android.graphics.RectF;
import com.airbnb.lottie.u;
import com.airbnb.lottie.y;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes.dex */
public final class g implements e, com.airbnb.lottie.animation.keyframe.a, k {
    public final Path a;
    public final com.airbnb.lottie.animation.a b;
    public final com.airbnb.lottie.model.layer.b c;
    public final String d;
    public final boolean e;
    public final ArrayList f;
    public final com.airbnb.lottie.animation.keyframe.f g;
    public final com.airbnb.lottie.animation.keyframe.f h;
    public com.airbnb.lottie.animation.keyframe.r i;
    public final u j;
    public com.airbnb.lottie.animation.keyframe.e k;
    public float l;

    public g(u uVar, com.airbnb.lottie.model.layer.b bVar, com.airbnb.lottie.model.content.l lVar) {
        Path path = new Path();
        this.a = path;
        this.b = new com.airbnb.lottie.animation.a(1, 0);
        this.f = new ArrayList();
        this.c = bVar;
        this.d = lVar.c;
        this.e = lVar.f;
        this.j = uVar;
        if (bVar.l() != null) {
            com.airbnb.lottie.animation.keyframe.i iVarJ = ((com.airbnb.lottie.model.animatable.b) bVar.l().b).j();
            this.k = iVarJ;
            iVarJ.a(this);
            bVar.g(this.k);
        }
        com.airbnb.lottie.model.animatable.a aVar = lVar.d;
        if (aVar == null) {
            this.g = null;
            this.h = null;
            return;
        }
        com.airbnb.lottie.model.animatable.a aVar2 = lVar.e;
        path.setFillType(lVar.b);
        com.airbnb.lottie.animation.keyframe.e eVarJ = aVar.j();
        this.g = (com.airbnb.lottie.animation.keyframe.f) eVarJ;
        eVarJ.a(this);
        bVar.g(eVarJ);
        com.airbnb.lottie.animation.keyframe.e eVarJ2 = aVar2.j();
        this.h = (com.airbnb.lottie.animation.keyframe.f) eVarJ2;
        eVarJ2.a(this);
        bVar.g(eVarJ2);
    }

    @Override // com.airbnb.lottie.animation.keyframe.a
    public final void a() {
        this.j.invalidateSelf();
    }

    @Override // com.airbnb.lottie.animation.content.c
    public final void b(List list, List list2) {
        for (int i = 0; i < list2.size(); i++) {
            c cVar = (c) list2.get(i);
            if (cVar instanceof m) {
                this.f.add((m) cVar);
            }
        }
    }

    @Override // com.airbnb.lottie.animation.content.e
    public final void c(Canvas canvas, Matrix matrix, int i, com.airbnb.lottie.utils.a aVar) {
        BlurMaskFilter blurMaskFilter;
        if (this.e) {
            return;
        }
        com.airbnb.lottie.animation.keyframe.f fVar = this.g;
        float fIntValue = ((Integer) this.h.e()).intValue() / 100.0f;
        int iC = (com.airbnb.lottie.utils.g.c((int) (i * fIntValue)) << 24) | (fVar.l(fVar.c.b(), fVar.c()) & 16777215);
        com.airbnb.lottie.animation.a aVar2 = this.b;
        aVar2.setColor(iC);
        com.airbnb.lottie.animation.keyframe.r rVar = this.i;
        if (rVar != null) {
            aVar2.setColorFilter((ColorFilter) rVar.e());
        }
        com.airbnb.lottie.animation.keyframe.e eVar = this.k;
        if (eVar != null) {
            float fFloatValue = ((Float) eVar.e()).floatValue();
            if (fFloatValue == DefinitionKt.NO_Float_VALUE) {
                aVar2.setMaskFilter(null);
            } else if (fFloatValue != this.l) {
                com.airbnb.lottie.model.layer.b bVar = this.c;
                if (bVar.A == fFloatValue) {
                    blurMaskFilter = bVar.B;
                } else {
                    BlurMaskFilter blurMaskFilter2 = new BlurMaskFilter(fFloatValue / 2.0f, BlurMaskFilter.Blur.NORMAL);
                    bVar.B = blurMaskFilter2;
                    bVar.A = fFloatValue;
                    blurMaskFilter = blurMaskFilter2;
                }
                aVar2.setMaskFilter(blurMaskFilter);
            }
            this.l = fFloatValue;
        }
        if (aVar != null) {
            aVar.a((int) (fIntValue * 255.0f), aVar2);
        } else {
            aVar2.clearShadowLayer();
        }
        Path path = this.a;
        path.reset();
        int i2 = 0;
        while (true) {
            ArrayList arrayList = this.f;
            if (i2 >= arrayList.size()) {
                canvas.drawPath(path, aVar2);
                return;
            } else {
                path.addPath(((m) arrayList.get(i2)).h(), matrix);
                i2++;
            }
        }
    }

    @Override // com.airbnb.lottie.model.f
    public final void d(ColorFilter colorFilter, com.quizlet.data.repository.widget.b bVar) {
        PointF pointF = y.a;
        if (colorFilter == 1) {
            this.g.j(bVar);
            return;
        }
        if (colorFilter == 4) {
            this.h.j(bVar);
            return;
        }
        ColorFilter colorFilter2 = y.F;
        com.airbnb.lottie.model.layer.b bVar2 = this.c;
        if (colorFilter == colorFilter2) {
            com.airbnb.lottie.animation.keyframe.r rVar = this.i;
            if (rVar != null) {
                bVar2.o(rVar);
            }
            com.airbnb.lottie.animation.keyframe.r rVar2 = new com.airbnb.lottie.animation.keyframe.r(bVar, null);
            this.i = rVar2;
            rVar2.a(this);
            bVar2.g(this.i);
            return;
        }
        if (colorFilter == y.e) {
            com.airbnb.lottie.animation.keyframe.e eVar = this.k;
            if (eVar != null) {
                eVar.j(bVar);
                return;
            }
            com.airbnb.lottie.animation.keyframe.r rVar3 = new com.airbnb.lottie.animation.keyframe.r(bVar, null);
            this.k = rVar3;
            rVar3.a(this);
            bVar2.g(this.k);
        }
    }

    @Override // com.airbnb.lottie.model.f
    public final void e(com.airbnb.lottie.model.e eVar, int i, ArrayList arrayList, com.airbnb.lottie.model.e eVar2) {
        com.airbnb.lottie.utils.g.g(eVar, i, arrayList, eVar2, this);
    }

    @Override // com.airbnb.lottie.animation.content.e
    public final void f(RectF rectF, Matrix matrix, boolean z) {
        Path path = this.a;
        path.reset();
        int i = 0;
        while (true) {
            ArrayList arrayList = this.f;
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

    @Override // com.airbnb.lottie.animation.content.c
    public final String getName() {
        return this.d;
    }
}
