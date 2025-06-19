package com.airbnb.lottie.animation.content;

import java.util.ArrayList;
import java.util.List;

/* loaded from: classes.dex */
public final class t implements c, com.airbnb.lottie.animation.keyframe.a {
    public final boolean a;
    public final ArrayList b = new ArrayList();
    public final int c;
    public final com.airbnb.lottie.animation.keyframe.i d;
    public final com.airbnb.lottie.animation.keyframe.i e;
    public final com.airbnb.lottie.animation.keyframe.i f;

    public t(com.airbnb.lottie.model.layer.b bVar, com.airbnb.lottie.model.content.p pVar) {
        pVar.getClass();
        this.a = pVar.e;
        this.c = pVar.a;
        com.airbnb.lottie.animation.keyframe.i iVarJ = pVar.b.j();
        this.d = iVarJ;
        com.airbnb.lottie.animation.keyframe.i iVarJ2 = pVar.c.j();
        this.e = iVarJ2;
        com.airbnb.lottie.animation.keyframe.i iVarJ3 = pVar.d.j();
        this.f = iVarJ3;
        bVar.g(iVarJ);
        bVar.g(iVarJ2);
        bVar.g(iVarJ3);
        iVarJ.a(this);
        iVarJ2.a(this);
        iVarJ3.a(this);
    }

    @Override // com.airbnb.lottie.animation.keyframe.a
    public final void a() {
        int i = 0;
        while (true) {
            ArrayList arrayList = this.b;
            if (i >= arrayList.size()) {
                return;
            }
            ((com.airbnb.lottie.animation.keyframe.a) arrayList.get(i)).a();
            i++;
        }
    }

    @Override // com.airbnb.lottie.animation.content.c
    public final void b(List list, List list2) {
    }

    public final void d(com.airbnb.lottie.animation.keyframe.a aVar) {
        this.b.add(aVar);
    }
}
