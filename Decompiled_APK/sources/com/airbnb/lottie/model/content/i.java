package com.airbnb.lottie.model.content;

import com.airbnb.lottie.u;

/* loaded from: classes.dex */
public final class i implements b {
    public final /* synthetic */ int a = 1;
    public final String b;
    public final com.airbnb.lottie.model.animatable.b c;
    public final boolean d;
    public final com.airbnb.lottie.model.animatable.f e;
    public final Object f;

    public i(String str, com.airbnb.lottie.model.animatable.b bVar, com.airbnb.lottie.model.animatable.b bVar2, com.airbnb.lottie.model.animatable.e eVar, boolean z) {
        this.b = str;
        this.c = bVar;
        this.e = bVar2;
        this.f = eVar;
        this.d = z;
    }

    @Override // com.airbnb.lottie.model.content.b
    public final com.airbnb.lottie.animation.content.c a(u uVar, com.airbnb.lottie.h hVar, com.airbnb.lottie.model.layer.b bVar) {
        switch (this.a) {
            case 0:
                return new com.airbnb.lottie.animation.content.o(uVar, bVar, this);
            default:
                return new com.airbnb.lottie.animation.content.p(uVar, bVar, this);
        }
    }

    public String toString() {
        switch (this.a) {
            case 0:
                return "RectangleShape{position=" + this.e + ", size=" + ((com.airbnb.lottie.model.animatable.a) this.f) + '}';
            default:
                return super.toString();
        }
    }

    public i(String str, com.airbnb.lottie.model.animatable.f fVar, com.airbnb.lottie.model.animatable.a aVar, com.airbnb.lottie.model.animatable.b bVar, boolean z) {
        this.b = str;
        this.e = fVar;
        this.f = aVar;
        this.c = bVar;
        this.d = z;
    }
}
