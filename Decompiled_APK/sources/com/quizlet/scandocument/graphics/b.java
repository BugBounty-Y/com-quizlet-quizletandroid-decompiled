package com.quizlet.scandocument.graphics;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final float[] a;
    public final float[] b;
    public final int c;

    public b(a leftTop, a rightTop, a rightBottom, a leftBottom) {
        Intrinsics.checkNotNullParameter(leftTop, "leftTop");
        Intrinsics.checkNotNullParameter(rightTop, "rightTop");
        Intrinsics.checkNotNullParameter(rightBottom, "rightBottom");
        Intrinsics.checkNotNullParameter(leftBottom, "leftBottom");
        Float[] fArr = {Float.valueOf(leftTop.a), Float.valueOf(rightTop.a), Float.valueOf(rightBottom.a), Float.valueOf(leftBottom.a)};
        Intrinsics.checkNotNullParameter(fArr, "<this>");
        float[] fArr2 = new float[4];
        for (int i = 0; i < 4; i++) {
            fArr2[i] = fArr[i].floatValue();
        }
        Float[] fArr3 = {Float.valueOf(leftTop.b), Float.valueOf(rightTop.b), Float.valueOf(rightBottom.b), Float.valueOf(leftBottom.b)};
        Intrinsics.checkNotNullParameter(fArr3, "<this>");
        float[] fArr4 = new float[4];
        for (int i2 = 0; i2 < 4; i2++) {
            fArr4[i2] = fArr3[i2].floatValue();
        }
        this.a = fArr2;
        this.b = fArr4;
        this.c = 4;
    }
}
