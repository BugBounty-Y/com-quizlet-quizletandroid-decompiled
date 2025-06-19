package com.airbnb.lottie.animation.content;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Matrix;
import android.graphics.Path;
import android.graphics.RectF;
import com.airbnb.lottie.u;
import com.airbnb.lottie.y;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.ListIterator;

/* loaded from: classes.dex */
public final class p implements e, m, j, com.airbnb.lottie.animation.keyframe.a, k {
    public final Matrix a = new Matrix();
    public final Path b = new Path();
    public final u c;
    public final com.airbnb.lottie.model.layer.b d;
    public final String e;
    public final boolean f;
    public final com.airbnb.lottie.animation.keyframe.i g;
    public final com.airbnb.lottie.animation.keyframe.i h;
    public final com.airbnb.lottie.animation.keyframe.q i;
    public d j;

    public p(u uVar, com.airbnb.lottie.model.layer.b bVar, com.airbnb.lottie.model.content.i iVar) {
        this.c = uVar;
        this.d = bVar;
        this.e = iVar.b;
        this.f = iVar.d;
        com.airbnb.lottie.animation.keyframe.i iVarJ = iVar.c.j();
        this.g = iVarJ;
        bVar.g(iVarJ);
        iVarJ.a(this);
        com.airbnb.lottie.animation.keyframe.i iVarJ2 = ((com.airbnb.lottie.model.animatable.b) iVar.e).j();
        this.h = iVarJ2;
        bVar.g(iVarJ2);
        iVarJ2.a(this);
        com.airbnb.lottie.model.animatable.e eVar = (com.airbnb.lottie.model.animatable.e) iVar.f;
        eVar.getClass();
        com.airbnb.lottie.animation.keyframe.q qVar = new com.airbnb.lottie.animation.keyframe.q(eVar);
        this.i = qVar;
        qVar.a(bVar);
        qVar.b(this);
    }

    @Override // com.airbnb.lottie.animation.keyframe.a
    public final void a() {
        this.c.invalidateSelf();
    }

    @Override // com.airbnb.lottie.animation.content.c
    public final void b(List list, List list2) {
        this.j.b(list, list2);
    }

    @Override // com.airbnb.lottie.animation.content.e
    public final void c(Canvas canvas, Matrix matrix, int i, com.airbnb.lottie.utils.a aVar) {
        float fFloatValue = ((Float) this.g.e()).floatValue();
        float fFloatValue2 = ((Float) this.h.e()).floatValue();
        com.airbnb.lottie.animation.keyframe.q qVar = this.i;
        float fFloatValue3 = ((Float) ((com.airbnb.lottie.animation.keyframe.e) qVar.m).e()).floatValue() / 100.0f;
        float fFloatValue4 = ((Float) ((com.airbnb.lottie.animation.keyframe.e) qVar.n).e()).floatValue() / 100.0f;
        for (int i2 = ((int) fFloatValue) - 1; i2 >= 0; i2--) {
            Matrix matrix2 = this.a;
            matrix2.set(matrix);
            float f = i2;
            matrix2.preConcat(qVar.f(f + fFloatValue2));
            this.j.c(canvas, matrix2, (int) (com.airbnb.lottie.utils.g.f(fFloatValue3, fFloatValue4, f / fFloatValue) * i), aVar);
        }
    }

    @Override // com.airbnb.lottie.model.f
    public final void d(ColorFilter colorFilter, com.quizlet.data.repository.widget.b bVar) {
        if (this.i.c(colorFilter, bVar)) {
            return;
        }
        if (colorFilter == y.p) {
            this.g.j(bVar);
        } else if (colorFilter == y.q) {
            this.h.j(bVar);
        }
    }

    @Override // com.airbnb.lottie.model.f
    public final void e(com.airbnb.lottie.model.e eVar, int i, ArrayList arrayList, com.airbnb.lottie.model.e eVar2) {
        com.airbnb.lottie.utils.g.g(eVar, i, arrayList, eVar2, this);
        for (int i2 = 0; i2 < this.j.i.size(); i2++) {
            c cVar = (c) this.j.i.get(i2);
            if (cVar instanceof k) {
                com.airbnb.lottie.utils.g.g(eVar, i, arrayList, eVar2, (k) cVar);
            }
        }
    }

    @Override // com.airbnb.lottie.animation.content.e
    public final void f(RectF rectF, Matrix matrix, boolean z) {
        this.j.f(rectF, matrix, z);
    }

    @Override // com.airbnb.lottie.animation.content.j
    public final void g(ListIterator listIterator) {
        if (this.j != null) {
            return;
        }
        while (listIterator.hasPrevious() && listIterator.previous() != this) {
        }
        ArrayList arrayList = new ArrayList();
        while (listIterator.hasPrevious()) {
            arrayList.add((c) listIterator.previous());
            listIterator.remove();
        }
        Collections.reverse(arrayList);
        this.j = new d(this.c, this.d, "Repeater", this.f, arrayList, null);
    }

    @Override // com.airbnb.lottie.animation.content.c
    public final String getName() {
        return this.e;
    }

    @Override // com.airbnb.lottie.animation.content.m
    public final Path h() {
        Path pathH = this.j.h();
        Path path = this.b;
        path.reset();
        float fFloatValue = ((Float) this.g.e()).floatValue();
        float fFloatValue2 = ((Float) this.h.e()).floatValue();
        for (int i = ((int) fFloatValue) - 1; i >= 0; i--) {
            Matrix matrix = this.a;
            matrix.set(this.i.f(i + fFloatValue2));
            path.addPath(pathH, matrix);
        }
        return path;
    }
}
