package com.airbnb.lottie.animation.content;

import android.graphics.ColorFilter;
import android.graphics.Path;
import android.graphics.PointF;
import android.graphics.RectF;
import androidx.compose.ui.graphics.vector.C0868g;
import com.airbnb.lottie.u;
import com.airbnb.lottie.y;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class o implements com.airbnb.lottie.animation.keyframe.a, k, m {
    public final String c;
    public final boolean d;
    public final u e;
    public final com.airbnb.lottie.animation.keyframe.e f;
    public final com.airbnb.lottie.animation.keyframe.e g;
    public final com.airbnb.lottie.animation.keyframe.i h;
    public boolean k;
    public final Path a = new Path();
    public final RectF b = new RectF();
    public final C0868g i = new C0868g(1);
    public com.airbnb.lottie.animation.keyframe.e j = null;

    public o(u uVar, com.airbnb.lottie.model.layer.b bVar, com.airbnb.lottie.model.content.i iVar) {
        this.c = iVar.b;
        this.d = iVar.d;
        this.e = uVar;
        com.airbnb.lottie.animation.keyframe.e eVarJ = iVar.e.j();
        this.f = eVarJ;
        com.airbnb.lottie.animation.keyframe.e eVarJ2 = ((com.airbnb.lottie.model.animatable.a) iVar.f).j();
        this.g = eVarJ2;
        com.airbnb.lottie.animation.keyframe.i iVarJ = iVar.c.j();
        this.h = iVarJ;
        bVar.g(eVarJ);
        bVar.g(eVarJ2);
        bVar.g(iVarJ);
        eVarJ.a(this);
        eVarJ2.a(this);
        iVarJ.a(this);
    }

    @Override // com.airbnb.lottie.animation.keyframe.a
    public final void a() {
        this.k = false;
        this.e.invalidateSelf();
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0027  */
    @Override // com.airbnb.lottie.animation.content.c
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(java.util.List r5, java.util.List r6) {
        /*
            r4 = this;
            r6 = 0
        L1:
            r0 = r5
            java.util.ArrayList r0 = (java.util.ArrayList) r0
            int r1 = r0.size()
            if (r6 >= r1) goto L34
            java.lang.Object r0 = r0.get(r6)
            com.airbnb.lottie.animation.content.c r0 = (com.airbnb.lottie.animation.content.c) r0
            boolean r1 = r0 instanceof com.airbnb.lottie.animation.content.t
            if (r1 == 0) goto L27
            r1 = r0
            com.airbnb.lottie.animation.content.t r1 = (com.airbnb.lottie.animation.content.t) r1
            int r2 = r1.c
            r3 = 1
            if (r2 != r3) goto L27
            androidx.compose.ui.graphics.vector.g r0 = r4.i
            java.util.ArrayList r0 = r0.a
            r0.add(r1)
            r1.d(r4)
            goto L31
        L27:
            boolean r1 = r0 instanceof com.airbnb.lottie.animation.content.q
            if (r1 == 0) goto L31
            com.airbnb.lottie.animation.content.q r0 = (com.airbnb.lottie.animation.content.q) r0
            com.airbnb.lottie.animation.keyframe.e r0 = r0.b
            r4.j = r0
        L31:
            int r6 = r6 + 1
            goto L1
        L34:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.airbnb.lottie.animation.content.o.b(java.util.List, java.util.List):void");
    }

    @Override // com.airbnb.lottie.model.f
    public final void d(ColorFilter colorFilter, com.quizlet.data.repository.widget.b bVar) {
        if (colorFilter == y.g) {
            this.g.j(bVar);
        } else if (colorFilter == y.i) {
            this.f.j(bVar);
        } else if (colorFilter == y.h) {
            this.h.j(bVar);
        }
    }

    @Override // com.airbnb.lottie.model.f
    public final void e(com.airbnb.lottie.model.e eVar, int i, ArrayList arrayList, com.airbnb.lottie.model.e eVar2) {
        com.airbnb.lottie.utils.g.g(eVar, i, arrayList, eVar2, this);
    }

    @Override // com.airbnb.lottie.animation.content.c
    public final String getName() {
        return this.c;
    }

    @Override // com.airbnb.lottie.animation.content.m
    public final Path h() {
        float f;
        com.airbnb.lottie.animation.keyframe.e eVar;
        boolean z = this.k;
        Path path = this.a;
        if (z) {
            return path;
        }
        path.reset();
        if (this.d) {
            this.k = true;
            return path;
        }
        PointF pointF = (PointF) this.g.e();
        float f2 = pointF.x / 2.0f;
        float f3 = pointF.y / 2.0f;
        com.airbnb.lottie.animation.keyframe.i iVar = this.h;
        float fL = iVar == null ? 0.0f : iVar.l();
        if (fL == DefinitionKt.NO_Float_VALUE && (eVar = this.j) != null) {
            fL = Math.min(((Float) eVar.e()).floatValue(), Math.min(f2, f3));
        }
        float fMin = Math.min(f2, f3);
        if (fL > fMin) {
            fL = fMin;
        }
        PointF pointF2 = (PointF) this.f.e();
        path.moveTo(pointF2.x + f2, (pointF2.y - f3) + fL);
        path.lineTo(pointF2.x + f2, (pointF2.y + f3) - fL);
        RectF rectF = this.b;
        if (fL > DefinitionKt.NO_Float_VALUE) {
            float f4 = pointF2.x + f2;
            float f5 = fL * 2.0f;
            f = 2.0f;
            float f6 = pointF2.y + f3;
            rectF.set(f4 - f5, f6 - f5, f4, f6);
            path.arcTo(rectF, DefinitionKt.NO_Float_VALUE, 90.0f, false);
        } else {
            f = 2.0f;
        }
        path.lineTo((pointF2.x - f2) + fL, pointF2.y + f3);
        if (fL > DefinitionKt.NO_Float_VALUE) {
            float f7 = pointF2.x - f2;
            float f8 = pointF2.y + f3;
            float f9 = fL * f;
            rectF.set(f7, f8 - f9, f9 + f7, f8);
            path.arcTo(rectF, 90.0f, 90.0f, false);
        }
        path.lineTo(pointF2.x - f2, (pointF2.y - f3) + fL);
        if (fL > DefinitionKt.NO_Float_VALUE) {
            float f10 = pointF2.x - f2;
            float f11 = pointF2.y - f3;
            float f12 = fL * f;
            rectF.set(f10, f11, f10 + f12, f12 + f11);
            path.arcTo(rectF, 180.0f, 90.0f, false);
        }
        path.lineTo((pointF2.x + f2) - fL, pointF2.y - f3);
        if (fL > DefinitionKt.NO_Float_VALUE) {
            float f13 = pointF2.x + f2;
            float f14 = fL * f;
            float f15 = pointF2.y - f3;
            rectF.set(f13 - f14, f15, f13, f14 + f15);
            path.arcTo(rectF, 270.0f, 90.0f, false);
        }
        path.close();
        this.i.a(path);
        this.k = true;
        return path;
    }
}
