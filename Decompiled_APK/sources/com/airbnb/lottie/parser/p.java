package com.airbnb.lottie.parser;

import android.graphics.Matrix;
import android.graphics.PointF;
import android.view.animation.BaseInterpolator;
import android.view.animation.LinearInterpolator;
import android.view.animation.PathInterpolator;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public abstract class p {
    public static final LinearInterpolator a = new LinearInterpolator();
    public static final com.airbnb.lottie.parser.moshi.c b = com.airbnb.lottie.parser.moshi.c.a("t", "s", "e", "o", "i", "h", "to", "ti");
    public static final com.airbnb.lottie.parser.moshi.c c = com.airbnb.lottie.parser.moshi.c.a("x", "y");

    public static BaseInterpolator a(PointF pointF, PointF pointF2) {
        pointF.x = com.airbnb.lottie.utils.g.b(pointF.x, -1.0f, 1.0f);
        pointF.y = com.airbnb.lottie.utils.g.b(pointF.y, -100.0f, 100.0f);
        pointF2.x = com.airbnb.lottie.utils.g.b(pointF2.x, -1.0f, 1.0f);
        float fB = com.airbnb.lottie.utils.g.b(pointF2.y, -100.0f, 100.0f);
        pointF2.y = fB;
        Matrix matrix = com.airbnb.lottie.utils.i.a;
        try {
            return new PathInterpolator(pointF.x, pointF.y, pointF2.x, fB);
        } catch (IllegalArgumentException e) {
            return "The Path cannot loop back on itself.".equals(e.getMessage()) ? new PathInterpolator(Math.min(pointF.x, 1.0f), pointF.y, Math.max(pointF2.x, DefinitionKt.NO_Float_VALUE), pointF2.y) : new LinearInterpolator();
        }
    }

    /* JADX WARN: Failed to find 'out' block for switch in B:9:0x002d. Please report as an issue. */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:100:0x0200  */
    /* JADX WARN: Type inference failed for: r3v12, types: [android.view.animation.BaseInterpolator] */
    /* JADX WARN: Type inference failed for: r3v4, types: [android.view.animation.BaseInterpolator] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.airbnb.lottie.value.a b(com.airbnb.lottie.parser.moshi.d r26, com.airbnb.lottie.h r27, float r28, com.airbnb.lottie.parser.E r29, boolean r30, boolean r31) {
        /*
            Method dump skipped, instructions count: 714
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.airbnb.lottie.parser.p.b(com.airbnb.lottie.parser.moshi.d, com.airbnb.lottie.h, float, com.airbnb.lottie.parser.E, boolean, boolean):com.airbnb.lottie.value.a");
    }
}
