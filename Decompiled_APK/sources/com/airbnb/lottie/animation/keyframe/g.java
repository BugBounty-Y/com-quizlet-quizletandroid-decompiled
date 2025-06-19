package com.airbnb.lottie.animation.keyframe;

import com.airbnb.lottie.E;

/* loaded from: classes.dex */
public final class g extends com.quizlet.data.repository.widget.b {
    public final /* synthetic */ com.quizlet.data.repository.widget.b d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(com.quizlet.data.repository.widget.b bVar) {
        super(6);
        this.d = bVar;
    }

    @Override // com.quizlet.data.repository.widget.b
    public final Object m(com.airbnb.lottie.value.b bVar) {
        Float f = (Float) ((E) this.d.c);
        if (f == null) {
            return null;
        }
        return Float.valueOf(f.floatValue() * 2.55f);
    }
}
