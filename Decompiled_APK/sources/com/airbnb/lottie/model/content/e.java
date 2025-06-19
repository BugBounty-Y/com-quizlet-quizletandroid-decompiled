package com.airbnb.lottie.model.content;

import com.airbnb.lottie.u;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class e implements b {
    public final String a;
    public final int b;
    public final com.airbnb.lottie.model.animatable.a c;
    public final com.airbnb.lottie.model.animatable.a d;
    public final com.airbnb.lottie.model.animatable.a e;
    public final com.airbnb.lottie.model.animatable.a f;
    public final com.airbnb.lottie.model.animatable.b g;
    public final int h;
    public final int i;
    public final float j;
    public final ArrayList k;
    public final com.airbnb.lottie.model.animatable.b l;
    public final boolean m;

    public e(String str, int i, com.airbnb.lottie.model.animatable.a aVar, com.airbnb.lottie.model.animatable.a aVar2, com.airbnb.lottie.model.animatable.a aVar3, com.airbnb.lottie.model.animatable.a aVar4, com.airbnb.lottie.model.animatable.b bVar, int i2, int i3, float f, ArrayList arrayList, com.airbnb.lottie.model.animatable.b bVar2, boolean z) {
        this.a = str;
        this.b = i;
        this.c = aVar;
        this.d = aVar2;
        this.e = aVar3;
        this.f = aVar4;
        this.g = bVar;
        this.h = i2;
        this.i = i3;
        this.j = f;
        this.k = arrayList;
        this.l = bVar2;
        this.m = z;
    }

    @Override // com.airbnb.lottie.model.content.b
    public final com.airbnb.lottie.animation.content.c a(u uVar, com.airbnb.lottie.h hVar, com.airbnb.lottie.model.layer.b bVar) {
        return new com.airbnb.lottie.animation.content.i(uVar, bVar, this);
    }
}
