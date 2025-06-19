package com.airbnb.lottie.animation.keyframe;

/* loaded from: classes.dex */
public final class i extends k {
    @Override // com.airbnb.lottie.animation.keyframe.e
    public final Object f(com.airbnb.lottie.value.a aVar, float f) {
        return Float.valueOf(m(aVar, f));
    }

    public final float l() {
        return m(this.c.b(), c());
    }

    public final float m(com.airbnb.lottie.value.a aVar, float f) {
        float f2;
        if (aVar.b == null || aVar.c == null) {
            throw new IllegalStateException("Missing values for keyframe.");
        }
        com.quizlet.data.repository.widget.b bVar = this.e;
        Object obj = aVar.b;
        if (bVar != null) {
            Float f3 = (Float) aVar.c;
            float fD = d();
            float f4 = this.d;
            f2 = f;
            Float f5 = (Float) bVar.n(aVar.g, aVar.h.floatValue(), (Float) obj, f3, f2, fD, f4);
            if (f5 != null) {
                return f5.floatValue();
            }
        } else {
            f2 = f;
        }
        if (aVar.i == -3987645.8f) {
            aVar.i = ((Float) obj).floatValue();
        }
        float f6 = aVar.i;
        if (aVar.j == -3987645.8f) {
            aVar.j = ((Float) aVar.c).floatValue();
        }
        return com.airbnb.lottie.utils.g.f(f6, aVar.j, f2);
    }
}
