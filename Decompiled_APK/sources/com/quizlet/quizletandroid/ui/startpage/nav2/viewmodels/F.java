package com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class F extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ L k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public F(L l, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = l;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new F(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((F) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:19:0x005a, code lost:
    
        if (r7 == r0) goto L20;
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
            r2 = 0
            r3 = 2
            r4 = 1
            com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L r5 = r6.k
            if (r1 == 0) goto L1f
            if (r1 == r4) goto L1b
            if (r1 != r3) goto L13
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L5d
        L13:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L1b:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L39
        L1f:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            com.quizlet.data.repository.folderwithcreatorinclass.e r7 = r5.l
            r6.j = r4
            r7.getClass()
            com.quizlet.data.interactor.qincentives.d r1 = new com.quizlet.data.interactor.qincentives.d
            r1.<init>(r7, r2)
            java.lang.Object r7 = r7.e
            kotlinx.coroutines.y r7 = (kotlinx.coroutines.AbstractC5040y) r7
            java.lang.Object r7 = kotlinx.coroutines.E.J(r7, r1, r6)
            if (r7 != r0) goto L39
            goto L5c
        L39:
            java.lang.Boolean r7 = (java.lang.Boolean) r7
            boolean r7 = r7.booleanValue()
            if (r7 == 0) goto L6a
            com.quizlet.data.repository.folderwithcreatorinclass.e r7 = r5.l
            r6.j = r3
            r7.getClass()
            com.quizlet.data.interactor.qincentives.a r1 = new com.quizlet.data.interactor.qincentives.a
            r1.<init>(r7, r2)
            java.lang.Object r7 = r7.e
            kotlinx.coroutines.y r7 = (kotlinx.coroutines.AbstractC5040y) r7
            java.lang.Object r7 = kotlinx.coroutines.E.J(r7, r1, r6)
            if (r7 != r0) goto L58
            goto L5a
        L58:
            kotlin.Unit r7 = kotlin.Unit.a
        L5a:
            if (r7 != r0) goto L5d
        L5c:
            return r0
        L5d:
            com.quizlet.eventlogger.features.qincentives.QIncentivesEventLogger r7 = r5.m
            r7.a()
            kotlinx.coroutines.flow.d0 r7 = r5.p
            com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.P r0 = com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.P.a
            r7.h(r0)
            goto L7a
        L6a:
            r5.getClass()
            androidx.lifecycle.viewmodel.internal.a r7 = androidx.lifecycle.p0.j(r5)
            com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.E r0 = new com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.E
            r0.<init>(r5, r2)
            r1 = 3
            kotlinx.coroutines.E.A(r7, r2, r2, r0, r1)
        L7a:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.F.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
