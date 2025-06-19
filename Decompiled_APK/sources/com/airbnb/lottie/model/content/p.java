package com.airbnb.lottie.model.content;

import com.airbnb.lottie.animation.content.t;
import com.airbnb.lottie.u;

/* loaded from: classes.dex */
public final class p implements b {
    public final int a;
    public final com.airbnb.lottie.model.animatable.b b;
    public final com.airbnb.lottie.model.animatable.b c;
    public final com.airbnb.lottie.model.animatable.b d;
    public final boolean e;

    public p(String str, int i, com.airbnb.lottie.model.animatable.b bVar, com.airbnb.lottie.model.animatable.b bVar2, com.airbnb.lottie.model.animatable.b bVar3, boolean z) {
        this.a = i;
        this.b = bVar;
        this.c = bVar2;
        this.d = bVar3;
        this.e = z;
    }

    @Override // com.airbnb.lottie.model.content.b
    public final com.airbnb.lottie.animation.content.c a(u uVar, com.airbnb.lottie.h hVar, com.airbnb.lottie.model.layer.b bVar) {
        return new t(bVar, this);
    }

    public final String toString() {
        return "Trim Path: {start: " + this.b + ", end: " + this.c + ", offset: " + this.d + "}";
    }
}
