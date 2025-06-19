package com.quizlet.assembly.compose.buttons;

import androidx.compose.animation.core.C0238e;
import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class a0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ kotlin.jvm.internal.G k;
    public final /* synthetic */ C0238e l;
    public final /* synthetic */ Function1 m;
    public final /* synthetic */ C4089n n;
    public final /* synthetic */ InterfaceC0773a0 o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a0(kotlin.jvm.internal.G g, C0238e c0238e, Function1 function1, C4089n c4089n, InterfaceC0773a0 interfaceC0773a0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = g;
        this.l = c0238e;
        this.m = function1;
        this.n = c4089n;
        this.o = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new a0(this.k, this.l, this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:18:0x0055, code lost:
    
        if (r1.g(r12) == r0) goto L23;
     */
    /* JADX WARN: Removed duplicated region for block: B:11:0x0020  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:22:0x0087 -> B:11:0x0020). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r13) {
        /*
            r12 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r12.j
            kotlin.jvm.internal.G r2 = r12.k
            r3 = 1
            r4 = 1065353216(0x3f800000, float:1.0)
            r5 = 2
            if (r1 == 0) goto L1d
            if (r1 == r3) goto L19
            if (r1 != r5) goto L11
            goto L1d
        L11:
            java.lang.IllegalStateException r13 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r13.<init>(r0)
            throw r13
        L19:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L58
        L1d:
            androidx.glance.appwidget.protobuf.Z.e(r13)
        L20:
            androidx.compose.runtime.a0 r13 = r12.o
            java.lang.Object r1 = r13.getValue()
            java.lang.Boolean r1 = (java.lang.Boolean) r1
            boolean r1 = r1.booleanValue()
            if (r1 == 0) goto L8a
            float r1 = r2.a
            r6 = 0
            int r1 = (r1 > r6 ? 1 : (r1 == r6 ? 0 : -1))
            if (r1 < 0) goto L8a
            androidx.compose.animation.core.e r1 = r12.l
            java.lang.Object r7 = r1.d()
            java.lang.Number r7 = (java.lang.Number) r7
            float r7 = r7.floatValue()
            float r7 = r4 - r7
            float r7 = r7 / r4
            r2.a = r7
            int r6 = (r7 > r6 ? 1 : (r7 == r6 ? 0 : -1))
            if (r6 > 0) goto L5f
            java.lang.Boolean r6 = java.lang.Boolean.FALSE
            r13.setValue(r6)
            r12.j = r3
            java.lang.Object r13 = r1.g(r12)
            if (r13 != r0) goto L58
            goto L89
        L58:
            com.quizlet.assembly.compose.buttons.V r13 = com.quizlet.assembly.compose.buttons.V.a
            kotlin.jvm.functions.Function1 r1 = r12.m
            r1.invoke(r13)
        L5f:
            java.lang.Float r7 = new java.lang.Float
            r7.<init>(r4)
            com.quizlet.assembly.compose.buttons.n r13 = r12.n
            r13.getClass()
            r8 = 8000(0x1f40, double:3.9525E-320)
            float r13 = (float) r8
            float r1 = r2.a
            float r13 = r13 * r1
            int r13 = (int) r13
            com.quizlet.themes.a r1 = com.quizlet.themes.a.c
            androidx.compose.animation.core.x r1 = r1.b()
            r6 = 0
            androidx.compose.animation.core.K0 r8 = androidx.compose.animation.core.AbstractC0240f.r(r13, r6, r1, r5)
            r12.j = r5
            r9 = 0
            r11 = 12
            androidx.compose.animation.core.e r6 = r12.l
            r10 = r12
            java.lang.Object r13 = androidx.compose.animation.core.C0238e.c(r6, r7, r8, r9, r10, r11)
            if (r13 != r0) goto L20
        L89:
            return r0
        L8a:
            kotlin.Unit r13 = kotlin.Unit.a
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.assembly.compose.buttons.a0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
