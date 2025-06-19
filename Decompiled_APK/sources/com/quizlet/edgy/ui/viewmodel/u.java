package com.quizlet.edgy.ui.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class u extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ w k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public u(w wVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = wVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new u(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((u) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:17:0x005e, code lost:
    
        if (r8 == r0) goto L18;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r8) throws java.lang.Throwable {
        /*
            r7 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.j
            r2 = 0
            r3 = 2
            r4 = 1
            com.quizlet.edgy.ui.viewmodel.w r5 = r7.k
            if (r1 == 0) goto L1f
            if (r1 == r4) goto L1b
            if (r1 != r3) goto L13
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L61
        L13:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L1b:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L39
        L1f:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.quizlet.data.repository.studysetwithcreatorinclass.g r8 = r5.b
            r7.j = r4
            r8.getClass()
            com.quizlet.edgy.utils.b r1 = new com.quizlet.edgy.utils.b
            r1.<init>(r8, r2)
            java.lang.Object r8 = r8.c
            kotlinx.coroutines.y r8 = (kotlinx.coroutines.AbstractC5040y) r8
            java.lang.Object r8 = kotlinx.coroutines.E.J(r8, r1, r7)
            if (r8 != r0) goto L39
            goto L60
        L39:
            java.util.List r8 = (java.util.List) r8
            kotlinx.coroutines.flow.s0 r1 = r5.f
        L3d:
            java.lang.Object r4 = r1.getValue()
            r6 = r4
            java.util.List r6 = (java.util.List) r6
            boolean r4 = r1.k(r4, r8)
            if (r4 == 0) goto L3d
            r7.j = r3
            com.quizlet.data.repository.studysetwithcreatorinclass.g r8 = r5.b
            r8.getClass()
            com.quizlet.edgy.utils.c r1 = new com.quizlet.edgy.utils.c
            r1.<init>(r8, r2)
            java.lang.Object r8 = r8.c
            kotlinx.coroutines.y r8 = (kotlinx.coroutines.AbstractC5040y) r8
            java.lang.Object r8 = kotlinx.coroutines.E.J(r8, r1, r7)
            if (r8 != r0) goto L61
        L60:
            return r0
        L61:
            r4 = r8
            java.util.List r4 = (java.util.List) r4
            kotlinx.coroutines.flow.s0 r6 = r5.g
        L66:
            java.lang.Object r8 = r6.getValue()
            r0 = r8
            java.util.List r0 = (java.util.List) r0
            boolean r8 = r6.k(r8, r4)
            if (r8 == 0) goto L66
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.edgy.ui.viewmodel.u.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
