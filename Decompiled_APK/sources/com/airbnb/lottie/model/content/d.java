package com.airbnb.lottie.model.content;

import android.graphics.Path;
import com.airbnb.lottie.u;

/* loaded from: classes.dex */
public final class d implements b {
    public final int a;
    public final Path.FillType b;
    public final com.airbnb.lottie.model.animatable.a c;
    public final com.airbnb.lottie.model.animatable.a d;
    public final com.airbnb.lottie.model.animatable.a e;
    public final com.airbnb.lottie.model.animatable.a f;
    public final String g;
    public final boolean h;

    public d(String str, int i, Path.FillType fillType, com.airbnb.lottie.model.animatable.a aVar, com.airbnb.lottie.model.animatable.a aVar2, com.airbnb.lottie.model.animatable.a aVar3, com.airbnb.lottie.model.animatable.a aVar4, boolean z) {
        this.a = i;
        this.b = fillType;
        this.c = aVar;
        this.d = aVar2;
        this.e = aVar3;
        this.f = aVar4;
        this.g = str;
        this.h = z;
    }

    @Override // com.airbnb.lottie.model.content.b
    public final com.airbnb.lottie.animation.content.c a(u uVar, com.airbnb.lottie.h hVar, com.airbnb.lottie.model.layer.b bVar) {
        return new com.airbnb.lottie.animation.content.h(uVar, hVar, bVar, this);
    }
}
