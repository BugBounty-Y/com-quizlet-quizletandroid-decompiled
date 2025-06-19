package com.quizlet.quizletandroid.ui.startpage.nav2;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.z, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4754z extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ Y k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4754z(Y y, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = y;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4754z(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4754z) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:25:0x0065, code lost:
    
        if (com.quizlet.quizletandroid.ui.startpage.nav2.Y.C(r6, r8, r7) == r0) goto L34;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x00a5, code lost:
    
        if (com.quizlet.quizletandroid.ui.startpage.nav2.Y.C(r6, r1, r7) != r0) goto L35;
     */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0058  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r8) {
        /*
            r7 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.j
            r2 = 1
            r3 = 4
            r4 = 3
            r5 = 2
            com.quizlet.quizletandroid.ui.startpage.nav2.Y r6 = r7.k
            if (r1 == 0) goto L2d
            if (r1 == r2) goto L29
            if (r1 == r5) goto L25
            if (r1 == r4) goto L21
            if (r1 != r3) goto L19
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto La8
        L19:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L21:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L7d
        L25:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L68
        L29:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L50
        L2d:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            androidx.lifecycle.Y r8 = r6.H
            java.lang.Boolean r1 = java.lang.Boolean.TRUE
            r8.j(r1)
            com.quizlet.infra.legacysyncengine.managers.d r8 = r6.g
            com.quizlet.db.data.models.persisted.DBUser r8 = r8.r
            if (r8 == 0) goto L44
            int r8 = r8.getSelfIdentifiedUserType()
            if (r8 != r2) goto L44
            goto L58
        L44:
            r7.j = r2
            com.quizlet.shared.usecase.folderstudymaterials.b r8 = r6.z
            r8.getClass()
            java.lang.Boolean r8 = java.lang.Boolean.FALSE
            if (r8 != r0) goto L50
            goto La7
        L50:
            java.lang.Boolean r8 = (java.lang.Boolean) r8
            boolean r8 = r8.booleanValue()
            if (r8 != 0) goto L72
        L58:
            com.quizlet.quizletandroid.ui.login.z r8 = new com.quizlet.quizletandroid.ui.login.z
            r1 = 10
            r8.<init>(r1)
            r7.j = r5
            java.lang.Object r8 = com.quizlet.quizletandroid.ui.startpage.nav2.Y.C(r6, r8, r7)
            if (r8 != r0) goto L68
            goto La7
        L68:
            androidx.lifecycle.Y r8 = r6.H
            java.lang.Boolean r0 = java.lang.Boolean.FALSE
            r8.j(r0)
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        L72:
            androidx.work.impl.model.e r8 = r6.l
            r7.j = r4
            java.lang.Object r8 = r8.o(r7)
            if (r8 != r0) goto L7d
            goto La7
        L7d:
            java.util.List r8 = (java.util.List) r8
            java.util.List r1 = r6.H(r8)
            com.quizlet.quizletandroid.ui.startpage.nav2.model.q r2 = r6.t
            r2.getClass()
            java.lang.String r4 = "data"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r1, r4)
            r2.g = r1
            androidx.lifecycle.Y r2 = r6.m1
            com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.l r4 = new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.l
            r4.<init>(r1)
            r2.j(r4)
            com.quizlet.features.achievements.ui.composables.i r1 = new com.quizlet.features.achievements.ui.composables.i
            r2 = 1
            r1.<init>(r8, r2)
            r7.j = r3
            java.lang.Object r8 = com.quizlet.quizletandroid.ui.startpage.nav2.Y.C(r6, r1, r7)
            if (r8 != r0) goto La8
        La7:
            return r0
        La8:
            androidx.lifecycle.Y r8 = r6.H
            java.lang.Boolean r0 = java.lang.Boolean.FALSE
            r8.j(r0)
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.startpage.nav2.C4754z.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
