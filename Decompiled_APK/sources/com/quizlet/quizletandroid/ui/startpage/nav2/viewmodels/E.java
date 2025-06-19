package com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class E extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ L k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public E(L l, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = l;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new E(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((E) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:16:0x003e, code lost:
    
        if (r6.emit(r1, r5) == r0) goto L17;
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
            com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L r4 = r5.k
            if (r1 == 0) goto L1e
            if (r1 == r3) goto L1a
            if (r1 != r2) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L48
        L12:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L2c
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            com.features.flashcards.creatormarketing.o r6 = r4.o
            r5.j = r3
            java.lang.Object r6 = r6.a(r5)
            if (r6 != r0) goto L2c
            goto L40
        L2c:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            boolean r6 = r6.booleanValue()
            if (r6 == 0) goto L41
            kotlinx.coroutines.flow.d0 r6 = r4.p
            com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.O r1 = com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.O.a
            r5.j = r2
            java.lang.Object r6 = r6.emit(r1, r5)
            if (r6 != r0) goto L48
        L40:
            return r0
        L41:
            com.quizlet.quizletandroid.ui.startpage.nav2.model.H r6 = com.quizlet.quizletandroid.ui.startpage.nav2.model.H.a
            androidx.lifecycle.X r0 = r4.s
            r0.j(r6)
        L48:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.E.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
