package com.quizlet.quizletandroid.ui.startpage.nav2;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class L extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Y j;
    public int k;
    public final /* synthetic */ Y l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public L(Y y, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = y;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new L(this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((L) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:22:0x007c, code lost:
    
        if (com.quizlet.quizletandroid.ui.startpage.nav2.Y.C(r4, r3, r6) == r0) goto L23;
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
            int r1 = r6.k
            r2 = 2
            r3 = 1
            com.quizlet.quizletandroid.ui.startpage.nav2.Y r4 = r6.l
            if (r1 == 0) goto L20
            if (r1 == r3) goto L1a
            if (r1 != r2) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L7f
        L12:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L1a:
            com.quizlet.quizletandroid.ui.startpage.nav2.Y r1 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L31
        L20:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            androidx.work.impl.model.e r7 = r4.l
            r6.j = r4
            r6.k = r3
            java.lang.Object r7 = r7.q(r6)
            if (r7 != r0) goto L30
            goto L7e
        L30:
            r1 = r4
        L31:
            java.util.List r7 = (java.util.List) r7
            r1.getClass()
            r1 = 0
            if (r7 == 0) goto L53
            boolean r3 = r7.isEmpty()
            if (r3 == 0) goto L40
            goto L53
        L40:
            java.util.ArrayList r7 = com.quizlet.quizletandroid.ui.startpage.nav2.Y.G(r7)
            com.quizlet.quizletandroid.ui.startpage.nav2.model.P r3 = com.quizlet.quizletandroid.ui.startpage.nav2.model.P.g
            java.util.ArrayList r7 = com.quizlet.quizletandroid.ui.startpage.nav2.Y.F(r7, r3, r1)
            java.util.ArrayList r7 = kotlin.collections.CollectionsKt.y0(r7)
            java.util.List r7 = kotlin.jvm.internal.O.b(r7)
            goto L58
        L53:
            java.util.ArrayList r7 = new java.util.ArrayList
            r7.<init>()
        L58:
            com.quizlet.quizletandroid.ui.startpage.nav2.model.q r3 = r4.t
            r3.getClass()
            java.lang.String r5 = "data"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r5)
            r3.i = r7
            androidx.lifecycle.Y r3 = r4.f1
            com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.l r5 = new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.l
            r5.<init>(r7)
            r3.j(r5)
            com.quizlet.features.achievements.ui.composables.i r3 = new com.quizlet.features.achievements.ui.composables.i
            r5 = 6
            r3.<init>(r7, r5)
            r6.j = r1
            r6.k = r2
            java.lang.Object r7 = com.quizlet.quizletandroid.ui.startpage.nav2.Y.C(r4, r3, r6)
            if (r7 != r0) goto L7f
        L7e:
            return r0
        L7f:
            androidx.lifecycle.Y r7 = r4.M
            java.lang.Boolean r0 = java.lang.Boolean.FALSE
            r7.j(r0)
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.startpage.nav2.L.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
