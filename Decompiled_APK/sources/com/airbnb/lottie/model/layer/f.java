package com.airbnb.lottie.model.layer;

import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.RectF;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class f extends b {
    @Override // com.airbnb.lottie.model.layer.b, com.airbnb.lottie.animation.content.e
    public final void f(RectF rectF, Matrix matrix, boolean z) {
        super.f(rectF, matrix, z);
        rectF.set(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE);
    }

    @Override // com.airbnb.lottie.model.layer.b
    public final void k(Canvas canvas, Matrix matrix, int i, com.airbnb.lottie.utils.a aVar) {
    }
}
