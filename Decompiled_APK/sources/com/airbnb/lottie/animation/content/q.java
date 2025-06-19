package com.airbnb.lottie.animation.content;

import com.airbnb.lottie.u;
import java.util.List;

/* loaded from: classes.dex */
public final class q implements com.airbnb.lottie.animation.keyframe.a, c {
    public final u a;
    public final com.airbnb.lottie.animation.keyframe.e b;
    public com.airbnb.lottie.model.content.k c;

    public q(u uVar, com.airbnb.lottie.model.layer.b bVar, com.airbnb.lottie.model.content.j jVar) {
        this.a = uVar;
        jVar.getClass();
        com.airbnb.lottie.animation.keyframe.i iVarJ = jVar.a.j();
        this.b = iVarJ;
        bVar.g(iVarJ);
        iVarJ.a(this);
    }

    public static int d(int i, int i2) {
        int i3 = i / i2;
        if ((i ^ i2) < 0 && i3 * i2 != i) {
            i3--;
        }
        return i - (i3 * i2);
    }

    @Override // com.airbnb.lottie.animation.keyframe.a
    public final void a() {
        this.a.invalidateSelf();
    }

    @Override // com.airbnb.lottie.animation.content.c
    public final void b(List list, List list2) {
    }
}
