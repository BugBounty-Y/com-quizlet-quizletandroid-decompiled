package com.google.android.gms.internal.mlkit_vision_barcode;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class Z {
    public static final /* synthetic */ int a = 0;

    /* JADX WARN: Code restructure failed: missing block: B:13:0x0011, code lost:
    
        if (r2 == false) goto L15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x0015, code lost:
    
        return r3 - r4;
     */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0026 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0027  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final int a(boolean r2, int r3, int r4, int r5) {
        /*
            r0 = 0
            if (r4 < r5) goto L8
            if (r2 == 0) goto L6
            return r0
        L6:
            int r5 = r5 - r4
            return r5
        L8:
            if (r2 != 0) goto Ld
            if (r4 > r3) goto L16
            goto L11
        Ld:
            int r1 = r5 - r4
            if (r1 <= r3) goto L16
        L11:
            if (r2 == 0) goto L14
            goto L21
        L14:
            int r3 = r3 - r4
            return r3
        L16:
            if (r2 == 0) goto L1b
            if (r4 > r3) goto L24
            goto L1f
        L1b:
            int r1 = r5 - r4
            if (r1 <= r3) goto L24
        L1f:
            if (r2 != 0) goto L22
        L21:
            return r3
        L22:
            int r3 = r3 - r4
            return r3
        L24:
            if (r2 != 0) goto L27
            return r0
        L27:
            int r5 = r5 - r4
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.Z.a(boolean, int, int, int):int");
    }

    public static final io.reactivex.rxjava3.core.p b(io.reactivex.rxjava3.core.p pVar, io.reactivex.rxjava3.core.p addend) {
        Intrinsics.checkNotNullParameter(pVar, "<this>");
        Intrinsics.checkNotNullParameter(addend, "addend");
        io.reactivex.rxjava3.core.p pVarP = io.reactivex.rxjava3.core.p.p(pVar, addend, com.quizlet.remote.util.d.a);
        Intrinsics.checkNotNullExpressionValue(pVarP, "zipWith(...)");
        return pVarP;
    }
}
