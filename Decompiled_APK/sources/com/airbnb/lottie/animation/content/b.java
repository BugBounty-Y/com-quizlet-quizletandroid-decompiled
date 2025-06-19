package com.airbnb.lottie.animation.content;

import android.graphics.ColorFilter;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PathMeasure;
import android.graphics.PointF;
import android.graphics.RectF;
import com.airbnb.lottie.u;
import com.airbnb.lottie.y;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;

/* loaded from: classes.dex */
public abstract class b implements com.airbnb.lottie.animation.keyframe.a, k, e {
    public final u e;
    public final com.airbnb.lottie.model.layer.b f;
    public final float[] h;
    public final com.airbnb.lottie.animation.a i;
    public final com.airbnb.lottie.animation.keyframe.i j;
    public final com.airbnb.lottie.animation.keyframe.f k;
    public final ArrayList l;
    public final com.airbnb.lottie.animation.keyframe.i m;
    public com.airbnb.lottie.animation.keyframe.r n;
    public com.airbnb.lottie.animation.keyframe.e o;
    public float p;
    public final PathMeasure a = new PathMeasure();
    public final Path b = new Path();
    public final Path c = new Path();
    public final RectF d = new RectF();
    public final ArrayList g = new ArrayList();

    public b(u uVar, com.airbnb.lottie.model.layer.b bVar, Paint.Cap cap, Paint.Join join, float f, com.airbnb.lottie.model.animatable.a aVar, com.airbnb.lottie.model.animatable.b bVar2, ArrayList arrayList, com.airbnb.lottie.model.animatable.b bVar3) {
        com.airbnb.lottie.animation.a aVar2 = new com.airbnb.lottie.animation.a(1, 0);
        this.i = aVar2;
        this.p = DefinitionKt.NO_Float_VALUE;
        this.e = uVar;
        this.f = bVar;
        aVar2.setStyle(Paint.Style.STROKE);
        aVar2.setStrokeCap(cap);
        aVar2.setStrokeJoin(join);
        aVar2.setStrokeMiter(f);
        this.k = (com.airbnb.lottie.animation.keyframe.f) aVar.j();
        this.j = bVar2.j();
        if (bVar3 == null) {
            this.m = null;
        } else {
            this.m = bVar3.j();
        }
        this.l = new ArrayList(arrayList.size());
        this.h = new float[arrayList.size()];
        for (int i = 0; i < arrayList.size(); i++) {
            this.l.add(((com.airbnb.lottie.model.animatable.b) arrayList.get(i)).j());
        }
        bVar.g(this.k);
        bVar.g(this.j);
        for (int i2 = 0; i2 < this.l.size(); i2++) {
            bVar.g((com.airbnb.lottie.animation.keyframe.e) this.l.get(i2));
        }
        com.airbnb.lottie.animation.keyframe.i iVar = this.m;
        if (iVar != null) {
            bVar.g(iVar);
        }
        this.k.a(this);
        this.j.a(this);
        for (int i3 = 0; i3 < arrayList.size(); i3++) {
            ((com.airbnb.lottie.animation.keyframe.e) this.l.get(i3)).a(this);
        }
        com.airbnb.lottie.animation.keyframe.i iVar2 = this.m;
        if (iVar2 != null) {
            iVar2.a(this);
        }
        if (bVar.l() != null) {
            com.airbnb.lottie.animation.keyframe.i iVarJ = ((com.airbnb.lottie.model.animatable.b) bVar.l().b).j();
            this.o = iVarJ;
            iVarJ.a(this);
            bVar.g(this.o);
        }
    }

    @Override // com.airbnb.lottie.animation.keyframe.a
    public final void a() {
        this.e.invalidateSelf();
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x0050  */
    @Override // com.airbnb.lottie.animation.content.c
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(java.util.List r8, java.util.List r9) {
        /*
            r7 = this;
            java.util.ArrayList r8 = (java.util.ArrayList) r8
            int r0 = r8.size()
            int r0 = r0 + (-1)
            r1 = 0
            r2 = r1
        La:
            r3 = 2
            if (r0 < 0) goto L21
            java.lang.Object r4 = r8.get(r0)
            com.airbnb.lottie.animation.content.c r4 = (com.airbnb.lottie.animation.content.c) r4
            boolean r5 = r4 instanceof com.airbnb.lottie.animation.content.t
            if (r5 == 0) goto L1e
            com.airbnb.lottie.animation.content.t r4 = (com.airbnb.lottie.animation.content.t) r4
            int r5 = r4.c
            if (r5 != r3) goto L1e
            r2 = r4
        L1e:
            int r0 = r0 + (-1)
            goto La
        L21:
            if (r2 == 0) goto L26
            r2.d(r7)
        L26:
            int r8 = r9.size()
            int r8 = r8 + (-1)
        L2c:
            java.util.ArrayList r0 = r7.g
            if (r8 < 0) goto L65
            java.lang.Object r4 = r9.get(r8)
            com.airbnb.lottie.animation.content.c r4 = (com.airbnb.lottie.animation.content.c) r4
            boolean r5 = r4 instanceof com.airbnb.lottie.animation.content.t
            if (r5 == 0) goto L50
            r5 = r4
            com.airbnb.lottie.animation.content.t r5 = (com.airbnb.lottie.animation.content.t) r5
            int r6 = r5.c
            if (r6 != r3) goto L50
            if (r1 == 0) goto L46
            r0.add(r1)
        L46:
            com.airbnb.lottie.animation.content.a r0 = new com.airbnb.lottie.animation.content.a
            r0.<init>(r5)
            r5.d(r7)
            r1 = r0
            goto L62
        L50:
            boolean r0 = r4 instanceof com.airbnb.lottie.animation.content.m
            if (r0 == 0) goto L62
            if (r1 != 0) goto L5b
            com.airbnb.lottie.animation.content.a r1 = new com.airbnb.lottie.animation.content.a
            r1.<init>(r2)
        L5b:
            java.util.ArrayList r0 = r1.a
            com.airbnb.lottie.animation.content.m r4 = (com.airbnb.lottie.animation.content.m) r4
            r0.add(r4)
        L62:
            int r8 = r8 + (-1)
            goto L2c
        L65:
            if (r1 == 0) goto L6a
            r0.add(r1)
        L6a:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.airbnb.lottie.animation.content.b.b(java.util.List, java.util.List):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:79:0x01f2  */
    @Override // com.airbnb.lottie.animation.content.e
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void c(android.graphics.Canvas r20, android.graphics.Matrix r21, int r22, com.airbnb.lottie.utils.a r23) {
        /*
            Method dump skipped, instructions count: 603
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.airbnb.lottie.animation.content.b.c(android.graphics.Canvas, android.graphics.Matrix, int, com.airbnb.lottie.utils.a):void");
    }

    @Override // com.airbnb.lottie.model.f
    public void d(ColorFilter colorFilter, com.quizlet.data.repository.widget.b bVar) {
        PointF pointF = y.a;
        if (colorFilter == 4) {
            this.k.j(bVar);
            return;
        }
        if (colorFilter == y.n) {
            this.j.j(bVar);
            return;
        }
        ColorFilter colorFilter2 = y.F;
        com.airbnb.lottie.model.layer.b bVar2 = this.f;
        if (colorFilter == colorFilter2) {
            com.airbnb.lottie.animation.keyframe.r rVar = this.n;
            if (rVar != null) {
                bVar2.o(rVar);
            }
            com.airbnb.lottie.animation.keyframe.r rVar2 = new com.airbnb.lottie.animation.keyframe.r(bVar, null);
            this.n = rVar2;
            rVar2.a(this);
            bVar2.g(this.n);
            return;
        }
        if (colorFilter == y.e) {
            com.airbnb.lottie.animation.keyframe.e eVar = this.o;
            if (eVar != null) {
                eVar.j(bVar);
                return;
            }
            com.airbnb.lottie.animation.keyframe.r rVar3 = new com.airbnb.lottie.animation.keyframe.r(bVar, null);
            this.o = rVar3;
            rVar3.a(this);
            bVar2.g(this.o);
        }
    }

    @Override // com.airbnb.lottie.model.f
    public final void e(com.airbnb.lottie.model.e eVar, int i, ArrayList arrayList, com.airbnb.lottie.model.e eVar2) {
        com.airbnb.lottie.utils.g.g(eVar, i, arrayList, eVar2, this);
    }

    @Override // com.airbnb.lottie.animation.content.e
    public final void f(RectF rectF, Matrix matrix, boolean z) {
        Path path = this.b;
        path.reset();
        int i = 0;
        while (true) {
            ArrayList arrayList = this.g;
            if (i >= arrayList.size()) {
                RectF rectF2 = this.d;
                path.computeBounds(rectF2, false);
                float fL = this.j.l() / 2.0f;
                rectF2.set(rectF2.left - fL, rectF2.top - fL, rectF2.right + fL, rectF2.bottom + fL);
                rectF.set(rectF2);
                rectF.set(rectF.left - 1.0f, rectF.top - 1.0f, rectF.right + 1.0f, rectF.bottom + 1.0f);
                return;
            }
            a aVar = (a) arrayList.get(i);
            for (int i2 = 0; i2 < aVar.a.size(); i2++) {
                path.addPath(((m) aVar.a.get(i2)).h(), matrix);
            }
            i++;
        }
    }
}
