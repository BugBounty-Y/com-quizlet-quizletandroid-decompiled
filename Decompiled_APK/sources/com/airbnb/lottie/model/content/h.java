package com.airbnb.lottie.model.content;

import com.airbnb.lottie.u;

/* loaded from: classes.dex */
public final class h implements b {
    public final String a;
    public final int b;
    public final com.airbnb.lottie.model.animatable.b c;
    public final com.airbnb.lottie.model.animatable.f d;
    public final com.airbnb.lottie.model.animatable.b e;
    public final com.airbnb.lottie.model.animatable.b f;
    public final com.airbnb.lottie.model.animatable.b g;
    public final com.airbnb.lottie.model.animatable.b h;
    public final com.airbnb.lottie.model.animatable.b i;
    public final boolean j;
    public final boolean k;

    public h(String str, int i, com.airbnb.lottie.model.animatable.b bVar, com.airbnb.lottie.model.animatable.f fVar, com.airbnb.lottie.model.animatable.b bVar2, com.airbnb.lottie.model.animatable.b bVar3, com.airbnb.lottie.model.animatable.b bVar4, com.airbnb.lottie.model.animatable.b bVar5, com.airbnb.lottie.model.animatable.b bVar6, boolean z, boolean z2) {
        this.a = str;
        this.b = i;
        this.c = bVar;
        this.d = fVar;
        this.e = bVar2;
        this.f = bVar3;
        this.g = bVar4;
        this.h = bVar5;
        this.i = bVar6;
        this.j = z;
        this.k = z2;
    }

    @Override // com.airbnb.lottie.model.content.b
    public final com.airbnb.lottie.animation.content.c a(u uVar, com.airbnb.lottie.h hVar, com.airbnb.lottie.model.layer.b bVar) {
        return new com.airbnb.lottie.animation.content.n(uVar, bVar, this);
    }
}
