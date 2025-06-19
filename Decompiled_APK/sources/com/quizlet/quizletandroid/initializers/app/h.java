package com.quizlet.quizletandroid.initializers.app;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ g k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(g gVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = gVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new h(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:17:0x006a, code lost:
    
        if (r7 == r0) goto L18;
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
            com.quizlet.quizletandroid.initializers.app.g r2 = r6.k
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L1e
            if (r1 == r4) goto L1a
            if (r1 != r3) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L6d
        L12:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L42
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r7 = r2
            com.quizlet.quizletandroid.u r7 = (com.quizlet.quizletandroid.u) r7
            com.quizlet.data.repository.login.a r1 = new com.quizlet.data.repository.login.a
            dagger.internal.c r5 = r7.Y0
            java.lang.Object r5 = r5.get()
            com.quizlet.quizletandroid.interactor.t r5 = (com.quizlet.quizletandroid.interactor.t) r5
            dagger.internal.c r7 = r7.o
            java.lang.Object r7 = r7.get()
            com.quizlet.usecase.b r7 = (com.quizlet.usecase.b) r7
            r1.<init>(r5, r7)
            r6.j = r4
            java.lang.Object r7 = r1.h(r6)
            if (r7 != r0) goto L42
            goto L6c
        L42:
            com.quizlet.quizletandroid.u r2 = (com.quizlet.quizletandroid.u) r2
            com.quizlet.data.repository.login.a r7 = new com.quizlet.data.repository.login.a
            dagger.internal.c r1 = r2.Y0
            java.lang.Object r1 = r1.get()
            com.quizlet.quizletandroid.interactor.t r1 = (com.quizlet.quizletandroid.interactor.t) r1
            dagger.internal.c r2 = r2.o
            java.lang.Object r2 = r2.get()
            com.quizlet.usecase.b r2 = (com.quizlet.usecase.b) r2
            r7.<init>(r1, r2)
            r6.j = r3
            kotlinx.coroutines.flow.internal.B r1 = kotlinx.coroutines.flow.internal.B.a
            java.lang.Object r7 = r7.c
            androidx.paging.J0 r7 = (androidx.paging.J0) r7
            java.lang.Object r7 = r7.b(r1, r6)
            if (r7 != r0) goto L68
            goto L6a
        L68:
            kotlin.Unit r7 = kotlin.Unit.a
        L6a:
            if (r7 != r0) goto L6d
        L6c:
            return r0
        L6d:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.initializers.app.h.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
