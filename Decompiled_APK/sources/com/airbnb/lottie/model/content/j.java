package com.airbnb.lottie.model.content;

import com.airbnb.lottie.animation.content.q;
import com.airbnb.lottie.u;

/* loaded from: classes.dex */
public final class j implements b {
    public final com.airbnb.lottie.model.animatable.b a;

    public j(String str, com.airbnb.lottie.model.animatable.b bVar) {
        this.a = bVar;
    }

    @Override // com.airbnb.lottie.model.content.b
    public final com.airbnb.lottie.animation.content.c a(u uVar, com.airbnb.lottie.h hVar, com.airbnb.lottie.model.layer.b bVar) {
        return new q(uVar, bVar, this);
    }
}
