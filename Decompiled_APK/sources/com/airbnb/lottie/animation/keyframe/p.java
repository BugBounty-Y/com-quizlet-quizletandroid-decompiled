package com.airbnb.lottie.animation.keyframe;

import android.graphics.PointF;
import com.airbnb.lottie.E;

/* loaded from: classes.dex */
public final class p extends com.quizlet.data.repository.widget.b {
    public final /* synthetic */ com.airbnb.lottie.value.b d;
    public final /* synthetic */ com.quizlet.data.repository.widget.b e;
    public final /* synthetic */ com.airbnb.lottie.model.b f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public p(com.airbnb.lottie.value.b bVar, com.quizlet.data.repository.widget.b bVar2, com.airbnb.lottie.model.b bVar3) {
        super(6);
        this.d = bVar;
        this.e = bVar2;
        this.f = bVar3;
    }

    @Override // com.quizlet.data.repository.widget.b
    public final Object m(com.airbnb.lottie.value.b bVar) {
        float f = bVar.a;
        float f2 = bVar.b;
        String str = ((com.airbnb.lottie.model.b) bVar.f).a;
        String str2 = ((com.airbnb.lottie.model.b) bVar.g).a;
        float f3 = bVar.c;
        float f4 = bVar.d;
        float f5 = bVar.e;
        com.airbnb.lottie.value.b bVar2 = this.d;
        bVar2.a = f;
        bVar2.b = f2;
        bVar2.f = str;
        bVar2.g = str2;
        bVar2.c = f3;
        bVar2.d = f4;
        bVar2.e = f5;
        String str3 = (String) ((E) this.e.c);
        com.airbnb.lottie.model.b bVar3 = (com.airbnb.lottie.model.b) (bVar.d == 1.0f ? bVar.g : bVar.f);
        String str4 = bVar3.b;
        float f6 = bVar3.c;
        int i = bVar3.d;
        int i2 = bVar3.e;
        float f7 = bVar3.f;
        float f8 = bVar3.g;
        int i3 = bVar3.h;
        int i4 = bVar3.i;
        float f9 = bVar3.j;
        boolean z = bVar3.k;
        PointF pointF = bVar3.l;
        PointF pointF2 = bVar3.m;
        com.airbnb.lottie.model.b bVar4 = this.f;
        bVar4.a = str3;
        bVar4.b = str4;
        bVar4.c = f6;
        bVar4.d = i;
        bVar4.e = i2;
        bVar4.f = f7;
        bVar4.g = f8;
        bVar4.h = i3;
        bVar4.i = i4;
        bVar4.j = f9;
        bVar4.k = z;
        bVar4.l = pointF;
        bVar4.m = pointF2;
        return bVar4;
    }
}
