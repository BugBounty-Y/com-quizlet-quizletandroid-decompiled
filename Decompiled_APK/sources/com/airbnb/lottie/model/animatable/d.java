package com.airbnb.lottie.model.animatable;

import com.airbnb.lottie.animation.keyframe.o;
import java.util.List;

/* loaded from: classes.dex */
public final class d implements f {
    public final b a;
    public final b b;

    public d(b bVar, b bVar2) {
        this.a = bVar;
        this.b = bVar2;
    }

    @Override // com.airbnb.lottie.model.animatable.f
    public final com.airbnb.lottie.animation.keyframe.e j() {
        return new o(this.a.j(), this.b.j());
    }

    @Override // com.airbnb.lottie.model.animatable.f
    public final List k() {
        throw new UnsupportedOperationException("Cannot call getKeyframes on AnimatableSplitDimensionPathValue.");
    }

    @Override // com.airbnb.lottie.model.animatable.f
    public final boolean l() {
        return this.a.l() && this.b.l();
    }
}
