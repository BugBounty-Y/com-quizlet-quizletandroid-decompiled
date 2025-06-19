package com.quizlet.quizletandroid.ui.library;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class G extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ c0 k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public G(c0 c0Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new G(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((G) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x003c, code lost:
    
        if (kotlinx.coroutines.flow.e0.i((kotlinx.coroutines.flow.InterfaceC4992i) r7, r1, r6) == r0) goto L15;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r7) throws java.lang.Throwable {
        /*
            r6 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.j
            com.quizlet.quizletandroid.ui.library.c0 r2 = r6.k
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L1e
            if (r1 == r4) goto L1a
            if (r1 != r3) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L3f
        L12:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L2e
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            com.quizlet.data.interactor.folderwithcreator.m r7 = r2.c
            r6.j = r4
            long r4 = r2.b
            java.lang.Object r7 = r7.j(r4, r6)
            if (r7 != r0) goto L2e
            goto L3e
        L2e:
            kotlinx.coroutines.flow.i r7 = (kotlinx.coroutines.flow.InterfaceC4992i) r7
            com.quizlet.quizletandroid.ui.library.F r1 = new com.quizlet.quizletandroid.ui.library.F
            r4 = 0
            r1.<init>(r2, r4)
            r6.j = r3
            java.lang.Object r7 = kotlinx.coroutines.flow.e0.i(r7, r1, r6)
            if (r7 != r0) goto L3f
        L3e:
            return r0
        L3f:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.library.G.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
