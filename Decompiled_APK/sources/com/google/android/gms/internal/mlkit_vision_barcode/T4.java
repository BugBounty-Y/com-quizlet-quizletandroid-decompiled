package com.google.android.gms.internal.mlkit_vision_barcode;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class T4 {
    public static final long a(float f, float f2) {
        return (Float.floatToRawIntBits(f2) & 4294967295L) | (Float.floatToRawIntBits(f) << 32);
    }

    /* JADX WARN: Removed duplicated region for block: B:94:0x01eb  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(com.quizlet.assembly.compose.menu.s r25, com.quizlet.features.folders.menu.u r26, java.lang.String r27, com.quizlet.generated.enums.y1 r28, kotlin.jvm.functions.Function2 r29, kotlin.jvm.functions.Function1 r30, kotlin.jvm.functions.Function0 r31, androidx.compose.ui.q r32, androidx.compose.runtime.InterfaceC0806l r33, int r34) {
        /*
            Method dump skipped, instructions count: 526
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.T4.b(com.quizlet.assembly.compose.menu.s, com.quizlet.features.folders.menu.u, java.lang.String, com.quizlet.generated.enums.y1, kotlin.jvm.functions.Function2, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function0, androidx.compose.ui.q, androidx.compose.runtime.l, int):void");
    }

    public static final long c(long j) {
        if (j != 9205357640488583168L) {
            return Q4.c(Float.intBitsToFloat((int) (j >> 32)) / 2.0f, Float.intBitsToFloat((int) (j & 4294967295L)) / 2.0f);
        }
        throw new IllegalStateException("Size is unspecified");
    }

    public static final Map d(Pair... pairs) {
        Intrinsics.checkNotNullParameter(pairs, "pairs");
        ArrayList arrayList = new ArrayList();
        for (Pair pair : pairs) {
            if (pair.b != null) {
                arrayList.add(pair);
            }
        }
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            if (next instanceof Pair) {
                arrayList2.add(next);
            }
        }
        Pair[] pairArr = (Pair[]) arrayList2.toArray(new Pair[0]);
        return kotlin.collections.V.f((Pair[]) Arrays.copyOf(pairArr, pairArr.length));
    }
}
