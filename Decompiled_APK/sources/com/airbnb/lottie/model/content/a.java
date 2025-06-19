package com.airbnb.lottie.model.content;

import com.airbnb.lottie.u;

/* loaded from: classes.dex */
public final class a implements b {
    public final String a;
    public final com.airbnb.lottie.model.animatable.f b;
    public final com.airbnb.lottie.model.animatable.a c;
    public final boolean d;
    public final boolean e;

    public a(String str, com.airbnb.lottie.model.animatable.f fVar, com.airbnb.lottie.model.animatable.a aVar, boolean z, boolean z2) {
        this.a = str;
        this.b = fVar;
        this.c = aVar;
        this.d = z;
        this.e = z2;
    }

    @Override // com.airbnb.lottie.model.content.b
    public final com.airbnb.lottie.animation.content.c a(u uVar, com.airbnb.lottie.h hVar, com.airbnb.lottie.model.layer.b bVar) {
        return new com.airbnb.lottie.animation.content.f(uVar, bVar, this);
    }
}
