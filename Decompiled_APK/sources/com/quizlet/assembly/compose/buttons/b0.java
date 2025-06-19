package com.quizlet.assembly.compose.buttons;

import androidx.compose.animation.core.C0238e;
import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class b0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ Function1 k;
    public final /* synthetic */ C0238e l;
    public final /* synthetic */ InterfaceC0773a0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b0(Function1 function1, C0238e c0238e, InterfaceC0773a0 interfaceC0773a0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = function1;
        this.l = c0238e;
        this.m = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new b0(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:16:0x0058, code lost:
    
        if (r5.l.f(r6, r5) != r0) goto L18;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r6) {
        /*
            r5 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r5.j
            r2 = 2
            r3 = 1
            if (r1 == 0) goto L1c
            if (r1 == r3) goto L18
            if (r1 != r2) goto L10
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L5b
        L10:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L18:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L49
        L1c:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            androidx.compose.runtime.a0 r6 = r5.m
            java.lang.Object r1 = r6.getValue()
            java.lang.Boolean r1 = (java.lang.Boolean) r1
            boolean r1 = r1.booleanValue()
            if (r1 == 0) goto L5b
            java.lang.Boolean r1 = java.lang.Boolean.FALSE
            r6.setValue(r1)
            com.quizlet.assembly.compose.buttons.X r6 = new com.quizlet.assembly.compose.buttons.X
            java.lang.String r1 = "app_paused"
            r6.<init>(r1)
            kotlin.jvm.functions.Function1 r1 = r5.k
            r1.invoke(r6)
            r5.j = r3
            r3 = 300(0x12c, double:1.48E-321)
            java.lang.Object r6 = kotlinx.coroutines.E.n(r3, r5)
            if (r6 != r0) goto L49
            goto L5a
        L49:
            java.lang.Float r6 = new java.lang.Float
            r1 = 1065353216(0x3f800000, float:1.0)
            r6.<init>(r1)
            r5.j = r2
            androidx.compose.animation.core.e r1 = r5.l
            java.lang.Object r6 = r1.f(r6, r5)
            if (r6 != r0) goto L5b
        L5a:
            return r0
        L5b:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.assembly.compose.buttons.b0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
