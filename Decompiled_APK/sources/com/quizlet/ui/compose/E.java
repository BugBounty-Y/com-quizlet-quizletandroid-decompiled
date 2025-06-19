package com.quizlet.ui.compose;

import androidx.compose.animation.core.C0238e;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class E extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C0238e k;
    public final /* synthetic */ float l;
    public final /* synthetic */ Function0 m;
    public final /* synthetic */ Function0 n;
    public final /* synthetic */ C0238e o;
    public final /* synthetic */ Function1 p;
    public final /* synthetic */ Function1 q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public E(C0238e c0238e, float f, Function0 function0, Function0 function02, C0238e c0238e2, Function1 function1, Function1 function12, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0238e;
        this.l = f;
        this.m = function0;
        this.n = function02;
        this.o = c0238e2;
        this.p = function1;
        this.q = function12;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new E(this.k, this.l, this.m, this.n, this.o, this.p, this.q, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((E) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:18:0x004e, code lost:
    
        if (com.google.android.gms.internal.mlkit_vision_barcode.B5.e(r5, r6.o, r6) == r0) goto L19;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r7) {
        /*
            r6 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.j
            r2 = 0
            r3 = 2
            r4 = 1
            androidx.compose.animation.core.e r5 = r6.k
            if (r1 == 0) goto L1f
            if (r1 == r4) goto L1b
            if (r1 != r3) goto L13
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L51
        L13:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L1b:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L2d
        L1f:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r6.j = r4
            float r7 = r6.l
            java.lang.Object r7 = com.google.android.gms.internal.mlkit_vision_barcode.B5.d(r5, r7, r6)
            if (r7 != r0) goto L2d
            goto L50
        L2d:
            java.lang.Object r7 = r5.d()
            java.lang.Number r7 = (java.lang.Number) r7
            float r7 = r7.floatValue()
            int r7 = (r7 > r2 ? 1 : (r7 == r2 ? 0 : -1))
            if (r7 <= 0) goto L41
            kotlin.jvm.functions.Function0 r7 = r6.m
            r7.invoke()
            goto L46
        L41:
            kotlin.jvm.functions.Function0 r7 = r6.n
            r7.invoke()
        L46:
            r6.j = r3
            androidx.compose.animation.core.e r7 = r6.o
            java.lang.Object r7 = com.google.android.gms.internal.mlkit_vision_barcode.B5.e(r5, r7, r6)
            if (r7 != r0) goto L51
        L50:
            return r0
        L51:
            java.lang.Float r7 = java.lang.Float.valueOf(r2)
            kotlin.jvm.functions.Function1 r0 = r6.p
            r0.invoke(r7)
            kotlin.jvm.functions.Function1 r0 = r6.q
            r0.invoke(r7)
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.ui.compose.E.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
