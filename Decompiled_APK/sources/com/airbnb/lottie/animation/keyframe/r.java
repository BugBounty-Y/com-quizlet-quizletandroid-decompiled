package com.airbnb.lottie.animation.keyframe;

import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Collections;

/* loaded from: classes.dex */
public final class r extends e {
    public final Object i;

    public r(com.quizlet.data.repository.widget.b bVar, Object obj) {
        super(Collections.EMPTY_LIST);
        j(bVar);
        this.i = obj;
    }

    @Override // com.airbnb.lottie.animation.keyframe.e
    public final float b() {
        return 1.0f;
    }

    @Override // com.airbnb.lottie.animation.keyframe.e
    public final Object e() {
        com.quizlet.data.repository.widget.b bVar = this.e;
        float f = this.d;
        Object obj = this.i;
        return bVar.n(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, obj, obj, f, f, f);
    }

    @Override // com.airbnb.lottie.animation.keyframe.e
    public final Object f(com.airbnb.lottie.value.a aVar, float f) {
        return e();
    }

    @Override // com.airbnb.lottie.animation.keyframe.e
    public final void h() {
        if (this.e != null) {
            super.h();
        }
    }

    @Override // com.airbnb.lottie.animation.keyframe.e
    public final void i(float f) {
        this.d = f;
    }
}
