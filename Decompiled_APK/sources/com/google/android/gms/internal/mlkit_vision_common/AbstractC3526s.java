package com.google.android.gms.internal.mlkit_vision_common;

import java.util.ArrayList;
import java.util.Arrays;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.s, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3526s {
    public static final /* synthetic */ int a = 0;

    public static com.airbnb.lottie.model.animatable.a a(com.airbnb.lottie.parser.moshi.e eVar, com.airbnb.lottie.h hVar) {
        return new com.airbnb.lottie.model.animatable.a(com.airbnb.lottie.parser.q.a(eVar, hVar, 1.0f, com.airbnb.lottie.parser.f.b, false), 0);
    }

    public static com.airbnb.lottie.model.animatable.b b(com.airbnb.lottie.parser.moshi.d dVar, com.airbnb.lottie.h hVar, boolean z) {
        return new com.airbnb.lottie.model.animatable.b(com.airbnb.lottie.parser.q.a(dVar, hVar, z ? com.airbnb.lottie.utils.i.c() : 1.0f, com.airbnb.lottie.parser.f.c, false));
    }

    public static com.airbnb.lottie.model.animatable.a c(com.airbnb.lottie.parser.moshi.e eVar, com.airbnb.lottie.h hVar, int i) {
        com.airbnb.lottie.parser.l lVar = new com.airbnb.lottie.parser.l(0);
        lVar.b = i;
        ArrayList arrayListA = com.airbnb.lottie.parser.q.a(eVar, hVar, 1.0f, lVar, false);
        for (int i2 = 0; i2 < arrayListA.size(); i2++) {
            com.airbnb.lottie.value.a aVar = (com.airbnb.lottie.value.a) arrayListA.get(i2);
            com.airbnb.lottie.model.content.c cVar = (com.airbnb.lottie.model.content.c) aVar.b;
            com.airbnb.lottie.model.content.c cVar2 = (com.airbnb.lottie.model.content.c) aVar.c;
            if (cVar != null && cVar2 != null) {
                float[] fArr = cVar.a;
                int length = fArr.length;
                float[] fArr2 = cVar2.a;
                if (length != fArr2.length) {
                    int length2 = fArr.length + fArr2.length;
                    float[] fArr3 = new float[length2];
                    System.arraycopy(fArr, 0, fArr3, 0, fArr.length);
                    System.arraycopy(fArr2, 0, fArr3, fArr.length, fArr2.length);
                    Arrays.sort(fArr3);
                    float f = Float.NaN;
                    int i3 = 0;
                    for (int i4 = 0; i4 < length2; i4++) {
                        float f2 = fArr3[i4];
                        if (f2 != f) {
                            fArr3[i3] = f2;
                            i3++;
                            f = fArr3[i4];
                        }
                    }
                    float[] fArrCopyOfRange = Arrays.copyOfRange(fArr3, 0, i3);
                    aVar = new com.airbnb.lottie.value.a(cVar.b(fArrCopyOfRange), cVar2.b(fArrCopyOfRange));
                }
            }
            arrayListA.set(i2, aVar);
        }
        return new com.airbnb.lottie.model.animatable.a(arrayListA, 1);
    }

    public static com.airbnb.lottie.model.animatable.a d(com.airbnb.lottie.parser.moshi.d dVar, com.airbnb.lottie.h hVar) {
        return new com.airbnb.lottie.model.animatable.a(com.airbnb.lottie.parser.q.a(dVar, hVar, 1.0f, com.airbnb.lottie.parser.f.d, false), 2);
    }

    public static com.airbnb.lottie.model.animatable.a e(com.airbnb.lottie.parser.moshi.e eVar, com.airbnb.lottie.h hVar) {
        return new com.airbnb.lottie.model.animatable.a(com.airbnb.lottie.parser.q.a(eVar, hVar, com.airbnb.lottie.utils.i.c(), com.airbnb.lottie.parser.f.f, true), 3);
    }
}
