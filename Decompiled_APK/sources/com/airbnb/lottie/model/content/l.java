package com.airbnb.lottie.model.content;

import android.graphics.Path;
import com.airbnb.lottie.u;

/* loaded from: classes.dex */
public final class l implements b {
    public final boolean a;
    public final Path.FillType b;
    public final String c;
    public final com.airbnb.lottie.model.animatable.a d;
    public final com.airbnb.lottie.model.animatable.a e;
    public final boolean f;

    public l(String str, boolean z, Path.FillType fillType, com.airbnb.lottie.model.animatable.a aVar, com.airbnb.lottie.model.animatable.a aVar2, boolean z2) {
        this.c = str;
        this.a = z;
        this.b = fillType;
        this.d = aVar;
        this.e = aVar2;
        this.f = z2;
    }

    @Override // com.airbnb.lottie.model.content.b
    public final com.airbnb.lottie.animation.content.c a(u uVar, com.airbnb.lottie.h hVar, com.airbnb.lottie.model.layer.b bVar) {
        return new com.airbnb.lottie.animation.content.g(uVar, bVar, this);
    }

    public final String toString() {
        return android.support.v4.media.session.a.u(new StringBuilder("ShapeFill{color=, fillEnabled="), this.a, '}');
    }
}
