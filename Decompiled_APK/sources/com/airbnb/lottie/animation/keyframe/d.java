package com.airbnb.lottie.animation.keyframe;

import java.util.List;

/* loaded from: classes.dex */
public final class d implements b {
    public final com.airbnb.lottie.value.a a;
    public float b = -1.0f;

    public d(List list) {
        this.a = (com.airbnb.lottie.value.a) list.get(0);
    }

    @Override // com.airbnb.lottie.animation.keyframe.b
    public final boolean a(float f) {
        if (this.b == f) {
            return true;
        }
        this.b = f;
        return false;
    }

    @Override // com.airbnb.lottie.animation.keyframe.b
    public final com.airbnb.lottie.value.a b() {
        return this.a;
    }

    @Override // com.airbnb.lottie.animation.keyframe.b
    public final boolean c(float f) {
        return !this.a.c();
    }

    @Override // com.airbnb.lottie.animation.keyframe.b
    public final float e() {
        return this.a.a();
    }

    @Override // com.airbnb.lottie.animation.keyframe.b
    public final float i() {
        return this.a.b();
    }

    @Override // com.airbnb.lottie.animation.keyframe.b
    public final boolean isEmpty() {
        return false;
    }
}
