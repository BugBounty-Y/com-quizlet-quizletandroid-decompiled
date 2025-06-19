package com.airbnb.lottie.model.content;

import com.airbnb.lottie.u;
import java.util.Arrays;
import java.util.List;

/* loaded from: classes.dex */
public final class m implements b {
    public final String a;
    public final List b;
    public final boolean c;

    public m(String str, List list, boolean z) {
        this.a = str;
        this.b = list;
        this.c = z;
    }

    @Override // com.airbnb.lottie.model.content.b
    public final com.airbnb.lottie.animation.content.c a(u uVar, com.airbnb.lottie.h hVar, com.airbnb.lottie.model.layer.b bVar) {
        return new com.airbnb.lottie.animation.content.d(uVar, bVar, this, hVar);
    }

    public final String toString() {
        return "ShapeGroup{name='" + this.a + "' Shapes: " + Arrays.toString(this.b.toArray()) + '}';
    }
}
