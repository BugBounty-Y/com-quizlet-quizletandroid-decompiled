package com.airbnb.lottie.model.layer;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Matrix;
import android.graphics.PointF;
import android.graphics.RectF;
import androidx.webkit.internal.p;
import com.airbnb.lottie.model.content.m;
import com.airbnb.lottie.u;
import com.airbnb.lottie.y;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/* loaded from: classes.dex */
public final class g extends b {
    public final com.airbnb.lottie.animation.content.d D;
    public final c E;
    public final com.airbnb.lottie.animation.keyframe.h F;

    public g(u uVar, e eVar, c cVar, com.airbnb.lottie.h hVar) {
        super(uVar, eVar);
        this.E = cVar;
        com.airbnb.lottie.animation.content.d dVar = new com.airbnb.lottie.animation.content.d(uVar, this, new m("__container", eVar.a, false), hVar);
        this.D = dVar;
        List list = Collections.EMPTY_LIST;
        dVar.b(list, list);
        com.quizlet.data.repository.studysetwithcreatorinclass.g gVar = this.p.x;
        if (gVar != null) {
            this.F = new com.airbnb.lottie.animation.keyframe.h(this, this, gVar);
        }
    }

    @Override // com.airbnb.lottie.model.layer.b, com.airbnb.lottie.model.f
    public final void d(ColorFilter colorFilter, com.quizlet.data.repository.widget.b bVar) {
        super.d(colorFilter, bVar);
        PointF pointF = y.a;
        com.airbnb.lottie.animation.keyframe.h hVar = this.F;
        if (colorFilter == 5 && hVar != null) {
            hVar.c.j(bVar);
            return;
        }
        if (colorFilter == y.B && hVar != null) {
            hVar.c(bVar);
            return;
        }
        if (colorFilter == y.C && hVar != null) {
            hVar.e.j(bVar);
            return;
        }
        if (colorFilter == y.D && hVar != null) {
            hVar.f.j(bVar);
        } else {
            if (colorFilter != y.E || hVar == null) {
                return;
            }
            hVar.g.j(bVar);
        }
    }

    @Override // com.airbnb.lottie.model.layer.b, com.airbnb.lottie.animation.content.e
    public final void f(RectF rectF, Matrix matrix, boolean z) {
        super.f(rectF, matrix, z);
        this.D.f(rectF, this.n, z);
    }

    @Override // com.airbnb.lottie.model.layer.b
    public final void k(Canvas canvas, Matrix matrix, int i, com.airbnb.lottie.utils.a aVar) {
        com.airbnb.lottie.animation.keyframe.h hVar = this.F;
        if (hVar != null) {
            aVar = hVar.b(matrix, i);
        }
        this.D.c(canvas, matrix, i, aVar);
    }

    @Override // com.airbnb.lottie.model.layer.b
    public final p l() {
        p pVar = this.p.w;
        return pVar != null ? pVar : this.E.p.w;
    }

    @Override // com.airbnb.lottie.model.layer.b
    public final void p(com.airbnb.lottie.model.e eVar, int i, ArrayList arrayList, com.airbnb.lottie.model.e eVar2) {
        this.D.e(eVar, i, arrayList, eVar2);
    }
}
