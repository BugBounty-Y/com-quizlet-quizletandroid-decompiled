package com.airbnb.lottie.model.content;

import com.airbnb.lottie.animation.content.s;
import com.airbnb.lottie.u;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class o implements b {
    public final String a;
    public final com.airbnb.lottie.model.animatable.b b;
    public final ArrayList c;
    public final com.airbnb.lottie.model.animatable.a d;
    public final com.airbnb.lottie.model.animatable.a e;
    public final com.airbnb.lottie.model.animatable.b f;
    public final int g;
    public final int h;
    public final float i;
    public final boolean j;

    public o(String str, com.airbnb.lottie.model.animatable.b bVar, ArrayList arrayList, com.airbnb.lottie.model.animatable.a aVar, com.airbnb.lottie.model.animatable.a aVar2, com.airbnb.lottie.model.animatable.b bVar2, int i, int i2, float f, boolean z) {
        this.a = str;
        this.b = bVar;
        this.c = arrayList;
        this.d = aVar;
        this.e = aVar2;
        this.f = bVar2;
        this.g = i;
        this.h = i2;
        this.i = f;
        this.j = z;
    }

    @Override // com.airbnb.lottie.model.content.b
    public final com.airbnb.lottie.animation.content.c a(u uVar, com.airbnb.lottie.h hVar, com.airbnb.lottie.model.layer.b bVar) {
        return new s(uVar, bVar, this);
    }
}
