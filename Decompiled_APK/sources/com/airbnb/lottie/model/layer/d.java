package com.airbnb.lottie.model.layer;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Matrix;
import android.graphics.Rect;
import android.graphics.RectF;
import com.airbnb.lottie.animation.keyframe.r;
import com.airbnb.lottie.u;
import com.airbnb.lottie.w;
import com.airbnb.lottie.y;
import com.android.billingclient.api.s;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.HashMap;

/* loaded from: classes.dex */
public final class d extends b {
    public final com.airbnb.lottie.animation.a D;
    public final Rect E;
    public final Rect F;
    public final RectF G;
    public final w H;
    public r I;
    public r J;
    public final com.airbnb.lottie.animation.keyframe.h K;
    public com.airbnb.lottie.utils.h L;
    public s M;

    public d(u uVar, e eVar) {
        w wVar;
        super(uVar, eVar);
        this.D = new com.airbnb.lottie.animation.a(3, 0);
        this.E = new Rect();
        this.F = new Rect();
        this.G = new RectF();
        com.airbnb.lottie.h hVar = uVar.a;
        if (hVar == null) {
            wVar = null;
        } else {
            wVar = (w) ((HashMap) hVar.c()).get(eVar.g);
        }
        this.H = wVar;
        com.quizlet.data.repository.studysetwithcreatorinclass.g gVar = this.p.x;
        if (gVar != null) {
            this.K = new com.airbnb.lottie.animation.keyframe.h(this, this, gVar);
        }
    }

    @Override // com.airbnb.lottie.model.layer.b, com.airbnb.lottie.model.f
    public final void d(ColorFilter colorFilter, com.quizlet.data.repository.widget.b bVar) {
        super.d(colorFilter, bVar);
        if (colorFilter == y.F) {
            this.I = new r(bVar, null);
            return;
        }
        if (colorFilter == y.I) {
            this.J = new r(bVar, null);
            return;
        }
        com.airbnb.lottie.animation.keyframe.h hVar = this.K;
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
        Bitmap bitmapS;
        super.f(rectF, matrix, z);
        w wVar = this.H;
        if (wVar != null) {
            float fC = com.airbnb.lottie.utils.i.c();
            boolean z2 = this.o.m;
            int i = wVar.b;
            int i2 = wVar.a;
            if (z2 || (bitmapS = s()) == null) {
                rectF.set(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, i2 * fC, i * fC);
            } else {
                rectF.set(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, bitmapS.getWidth() * fC, bitmapS.getHeight() * fC);
            }
            this.n.mapRect(rectF);
        }
    }

    @Override // com.airbnb.lottie.model.layer.b
    public final void k(Canvas canvas, Matrix matrix, int i, com.airbnb.lottie.utils.a aVar) {
        w wVar;
        Bitmap bitmapS = s();
        if (bitmapS == null || bitmapS.isRecycled() || (wVar = this.H) == null) {
            return;
        }
        float fC = com.airbnb.lottie.utils.i.c();
        com.airbnb.lottie.animation.a aVar2 = this.D;
        aVar2.setAlpha(i);
        r rVar = this.I;
        if (rVar != null) {
            aVar2.setColorFilter((ColorFilter) rVar.e());
        }
        com.airbnb.lottie.animation.keyframe.h hVar = this.K;
        if (hVar != null) {
            aVar = hVar.b(matrix, i);
        }
        int width = bitmapS.getWidth();
        int height = bitmapS.getHeight();
        Rect rect = this.E;
        rect.set(0, 0, width, height);
        boolean z = this.o.m;
        Rect rect2 = this.F;
        if (z) {
            rect2.set(0, 0, (int) (wVar.a * fC), (int) (wVar.b * fC));
        } else {
            rect2.set(0, 0, (int) (bitmapS.getWidth() * fC), (int) (bitmapS.getHeight() * fC));
        }
        boolean z2 = aVar != null;
        if (z2) {
            if (this.L == null) {
                this.L = new com.airbnb.lottie.utils.h();
            }
            if (this.M == null) {
                this.M = new s(7, (byte) 0);
            }
            s sVar = this.M;
            sVar.b = 255;
            sVar.c = null;
            aVar.getClass();
            com.airbnb.lottie.utils.a aVar3 = new com.airbnb.lottie.utils.a(aVar);
            sVar.c = aVar3;
            aVar3.b(i);
            RectF rectF = this.G;
            rectF.set(rect2.left, rect2.top, rect2.right, rect2.bottom);
            matrix.mapRect(rectF);
            canvas = this.L.e(canvas, rectF, this.M);
        }
        canvas.save();
        canvas.concat(matrix);
        canvas.drawBitmap(bitmapS, rect, rect2, aVar2);
        if (z2) {
            this.L.c();
        }
        canvas.restore();
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x002e  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x00b6  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.graphics.Bitmap s() {
        /*
            Method dump skipped, instructions count: 360
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.airbnb.lottie.model.layer.d.s():android.graphics.Bitmap");
    }
}
