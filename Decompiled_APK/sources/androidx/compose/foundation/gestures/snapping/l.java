package androidx.compose.foundation.gestures.snapping;

import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public abstract class l {
    public static final float a = 400;

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(androidx.compose.foundation.gestures.G0 r5, float r6, androidx.compose.animation.core.C0258o r7, androidx.compose.animation.core.C0276z r8, androidx.compose.foundation.gestures.snapping.d r9, kotlin.coroutines.jvm.internal.c r10) {
        /*
            boolean r0 = r10 instanceof androidx.compose.foundation.gestures.snapping.i
            if (r0 == 0) goto L13
            r0 = r10
            androidx.compose.foundation.gestures.snapping.i r0 = (androidx.compose.foundation.gestures.snapping.i) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            androidx.compose.foundation.gestures.snapping.i r0 = new androidx.compose.foundation.gestures.snapping.i
            r0.<init>(r10)
        L18:
            java.lang.Object r10 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            float r6 = r0.j
            kotlin.jvm.internal.G r5 = r0.l
            androidx.compose.animation.core.o r7 = r0.k
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L65
        L2d:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            kotlin.jvm.internal.G r10 = new kotlin.jvm.internal.G
            r10.<init>()
            java.lang.Object r2 = r7.a()
            java.lang.Number r2 = (java.lang.Number) r2
            float r2 = r2.floatValue()
            r4 = 0
            int r2 = (r2 > r4 ? 1 : (r2 == r4 ? 0 : -1))
            if (r2 != 0) goto L4e
            r2 = r3
            goto L4f
        L4e:
            r2 = 0
        L4f:
            r2 = r2 ^ r3
            androidx.compose.foundation.gestures.snapping.j r4 = new androidx.compose.foundation.gestures.snapping.j
            r4.<init>(r6, r10, r5, r9)
            r0.k = r7
            r0.l = r10
            r0.j = r6
            r0.n = r3
            java.lang.Object r5 = androidx.compose.animation.core.AbstractC0240f.f(r7, r8, r2, r4, r0)
            if (r5 != r1) goto L64
            return r1
        L64:
            r5 = r10
        L65:
            androidx.compose.foundation.gestures.snapping.a r8 = new androidx.compose.foundation.gestures.snapping.a
            float r5 = r5.a
            float r6 = r6 - r5
            java.lang.Float r5 = new java.lang.Float
            r5.<init>(r6)
            r8.<init>(r5, r7)
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.snapping.l.a(androidx.compose.foundation.gestures.G0, float, androidx.compose.animation.core.o, androidx.compose.animation.core.z, androidx.compose.foundation.gestures.snapping.d, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object b(androidx.compose.foundation.gestures.G0 r9, float r10, float r11, androidx.compose.animation.core.C0258o r12, androidx.compose.animation.core.C0253l0 r13, kotlin.jvm.functions.Function1 r14, kotlin.coroutines.jvm.internal.c r15) {
        /*
            boolean r0 = r15 instanceof androidx.compose.foundation.gestures.snapping.k
            if (r0 == 0) goto L14
            r0 = r15
            androidx.compose.foundation.gestures.snapping.k r0 = (androidx.compose.foundation.gestures.snapping.k) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L14
            int r1 = r1 - r2
            r0.o = r1
        L12:
            r6 = r0
            goto L1a
        L14:
            androidx.compose.foundation.gestures.snapping.k r0 = new androidx.compose.foundation.gestures.snapping.k
            r0.<init>(r15)
            goto L12
        L1a:
            java.lang.Object r15 = r6.n
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.o
            r7 = 0
            r2 = 1
            if (r1 == 0) goto L3a
            if (r1 != r2) goto L32
            float r9 = r6.k
            float r10 = r6.j
            kotlin.jvm.internal.G r11 = r6.m
            androidx.compose.animation.core.o r12 = r6.l
            androidx.glance.appwidget.protobuf.Z.e(r15)
            goto L80
        L32:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L3a:
            androidx.glance.appwidget.protobuf.Z.e(r15)
            kotlin.jvm.internal.G r15 = new kotlin.jvm.internal.G
            r15.<init>()
            java.lang.Object r1 = r12.a()
            java.lang.Number r1 = (java.lang.Number) r1
            float r8 = r1.floatValue()
            r1 = r2
            java.lang.Float r2 = new java.lang.Float
            r2.<init>(r10)
            java.lang.Object r3 = r12.a()
            java.lang.Number r3 = (java.lang.Number) r3
            float r3 = r3.floatValue()
            int r3 = (r3 > r7 ? 1 : (r3 == r7 ? 0 : -1))
            if (r3 != 0) goto L62
            r3 = r1
            goto L63
        L62:
            r3 = 0
        L63:
            r4 = r3 ^ 1
            androidx.compose.foundation.gestures.snapping.j r5 = new androidx.compose.foundation.gestures.snapping.j
            r5.<init>(r11, r15, r9, r14)
            r6.l = r12
            r6.m = r15
            r6.j = r10
            r6.k = r8
            r6.o = r1
            r1 = r12
            r3 = r13
            java.lang.Object r9 = androidx.compose.animation.core.AbstractC0240f.h(r1, r2, r3, r4, r5, r6)
            if (r9 != r0) goto L7d
            return r0
        L7d:
            r11 = r15
            r12 = r1
            r9 = r8
        L80:
            java.lang.Object r13 = r12.a()
            java.lang.Number r13 = (java.lang.Number) r13
            float r13 = r13.floatValue()
            float r9 = c(r13, r9)
            androidx.compose.foundation.gestures.snapping.a r13 = new androidx.compose.foundation.gestures.snapping.a
            float r11 = r11.a
            float r10 = r10 - r11
            java.lang.Float r11 = new java.lang.Float
            r11.<init>(r10)
            r10 = 29
            androidx.compose.animation.core.o r9 = androidx.compose.animation.core.AbstractC0240f.l(r12, r7, r9, r10)
            r13.<init>(r11, r9)
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.snapping.l.b(androidx.compose.foundation.gestures.G0, float, float, androidx.compose.animation.core.o, androidx.compose.animation.core.l0, kotlin.jvm.functions.Function1, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final float c(float f, float f2) {
        return f2 == DefinitionKt.NO_Float_VALUE ? DefinitionKt.NO_Float_VALUE : (f2 <= DefinitionKt.NO_Float_VALUE ? f >= f2 : f <= f2) ? f : f2;
    }
}
