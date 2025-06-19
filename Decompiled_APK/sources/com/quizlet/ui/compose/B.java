package com.quizlet.ui.compose;

import androidx.compose.animation.core.C0238e;
import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class B extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C0238e k;
    public final /* synthetic */ float l;
    public final /* synthetic */ C0238e m;
    public final /* synthetic */ InterfaceC0773a0 n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B(C0238e c0238e, float f, C0238e c0238e2, InterfaceC0773a0 interfaceC0773a0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0238e;
        this.l = f;
        this.m = c0238e2;
        this.n = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new B(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((B) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:19:0x0056, code lost:
    
        if (com.google.android.gms.internal.mlkit_vision_barcode.B5.e(r2, r9.m, r11) != r0) goto L21;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r12) {
        /*
            r11 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r11.j
            androidx.compose.animation.core.e r2 = r11.k
            r3 = 3
            r4 = 2
            r5 = 1
            if (r1 == 0) goto L28
            if (r1 == r5) goto L23
            if (r1 == r4) goto L1e
            if (r1 != r3) goto L16
            androidx.glance.appwidget.protobuf.Z.e(r12)
            r9 = r11
            goto L59
        L16:
            java.lang.IllegalStateException r12 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r12.<init>(r0)
            throw r12
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            r9 = r11
            goto L4e
        L23:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            r9 = r11
            goto L43
        L28:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            java.lang.Float r6 = new java.lang.Float
            r12 = 1051931443(0x3eb33333, float:0.35)
            r6.<init>(r12)
            r11.j = r5
            r8 = 0
            r10 = 14
            androidx.compose.animation.core.e r5 = r11.k
            r7 = 0
            r9 = r11
            java.lang.Object r12 = androidx.compose.animation.core.C0238e.c(r5, r6, r7, r8, r9, r10)
            if (r12 != r0) goto L43
            goto L58
        L43:
            r9.j = r4
            float r12 = r9.l
            java.lang.Object r12 = com.google.android.gms.internal.mlkit_vision_barcode.B5.d(r2, r12, r11)
            if (r12 != r0) goto L4e
            goto L58
        L4e:
            r9.j = r3
            androidx.compose.animation.core.e r12 = r9.m
            java.lang.Object r12 = com.google.android.gms.internal.mlkit_vision_barcode.B5.e(r2, r12, r11)
            if (r12 != r0) goto L59
        L58:
            return r0
        L59:
            androidx.compose.runtime.a0 r12 = r9.n
            java.lang.Object r12 = r12.getValue()
            kotlin.jvm.functions.Function0 r12 = (kotlin.jvm.functions.Function0) r12
            r12.invoke()
            kotlin.Unit r12 = kotlin.Unit.a
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.ui.compose.B.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
