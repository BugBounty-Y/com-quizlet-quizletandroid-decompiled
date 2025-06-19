package com.airbnb.lottie.animation.content;

import android.graphics.ColorFilter;
import android.graphics.Path;
import androidx.compose.ui.graphics.vector.C0868g;
import com.airbnb.lottie.u;
import com.airbnb.lottie.y;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes.dex */
public final class r implements m, com.airbnb.lottie.animation.keyframe.a, k {
    public final String b;
    public final boolean c;
    public final u d;
    public final com.airbnb.lottie.animation.keyframe.n e;
    public boolean f;
    public final Path a = new Path();
    public final C0868g g = new C0868g(1);

    public r(u uVar, com.airbnb.lottie.model.layer.b bVar, com.airbnb.lottie.model.content.n nVar) {
        this.b = nVar.a;
        this.c = nVar.d;
        this.d = uVar;
        com.airbnb.lottie.animation.keyframe.n nVar2 = new com.airbnb.lottie.animation.keyframe.n((List) nVar.c.b);
        this.e = nVar2;
        bVar.g(nVar2);
        nVar2.a(this);
    }

    @Override // com.airbnb.lottie.animation.keyframe.a
    public final void a() {
        this.f = false;
        this.d.invalidateSelf();
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0028  */
    @Override // com.airbnb.lottie.animation.content.c
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(java.util.List r6, java.util.List r7) {
        /*
            r5 = this;
            r7 = 0
            r0 = 0
        L2:
            r1 = r6
            java.util.ArrayList r1 = (java.util.ArrayList) r1
            int r2 = r1.size()
            if (r0 >= r2) goto L40
            java.lang.Object r1 = r1.get(r0)
            com.airbnb.lottie.animation.content.c r1 = (com.airbnb.lottie.animation.content.c) r1
            boolean r2 = r1 instanceof com.airbnb.lottie.animation.content.t
            if (r2 == 0) goto L28
            r2 = r1
            com.airbnb.lottie.animation.content.t r2 = (com.airbnb.lottie.animation.content.t) r2
            int r3 = r2.c
            r4 = 1
            if (r3 != r4) goto L28
            androidx.compose.ui.graphics.vector.g r1 = r5.g
            java.util.ArrayList r1 = r1.a
            r1.add(r2)
            r2.d(r5)
            goto L3d
        L28:
            boolean r2 = r1 instanceof com.airbnb.lottie.animation.content.q
            if (r2 == 0) goto L3d
            if (r7 != 0) goto L33
            java.util.ArrayList r7 = new java.util.ArrayList
            r7.<init>()
        L33:
            com.airbnb.lottie.animation.content.q r1 = (com.airbnb.lottie.animation.content.q) r1
            com.airbnb.lottie.animation.keyframe.e r2 = r1.b
            r2.a(r5)
            r7.add(r1)
        L3d:
            int r0 = r0 + 1
            goto L2
        L40:
            com.airbnb.lottie.animation.keyframe.n r6 = r5.e
            r6.m = r7
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.airbnb.lottie.animation.content.r.b(java.util.List, java.util.List):void");
    }

    @Override // com.airbnb.lottie.model.f
    public final void d(ColorFilter colorFilter, com.quizlet.data.repository.widget.b bVar) {
        if (colorFilter == y.K) {
            this.e.j(bVar);
        }
    }

    @Override // com.airbnb.lottie.model.f
    public final void e(com.airbnb.lottie.model.e eVar, int i, ArrayList arrayList, com.airbnb.lottie.model.e eVar2) {
        com.airbnb.lottie.utils.g.g(eVar, i, arrayList, eVar2, this);
    }

    @Override // com.airbnb.lottie.animation.content.c
    public final String getName() {
        return this.b;
    }

    @Override // com.airbnb.lottie.animation.content.m
    public final Path h() {
        boolean z = this.f;
        Path path = this.a;
        com.airbnb.lottie.animation.keyframe.n nVar = this.e;
        if (z && nVar.e == null) {
            return path;
        }
        path.reset();
        if (this.c) {
            this.f = true;
            return path;
        }
        Path path2 = (Path) nVar.e();
        if (path2 == null) {
            return path;
        }
        path.set(path2);
        path.setFillType(Path.FillType.EVEN_ODD);
        this.g.a(path);
        this.f = true;
        return path;
    }
}
