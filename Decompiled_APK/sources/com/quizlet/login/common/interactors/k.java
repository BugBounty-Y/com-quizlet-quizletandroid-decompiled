package com.quizlet.login.common.interactors;

import com.quizlet.db.data.models.persisted.DBUser;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public int j;
    public final /* synthetic */ androidx.compose.runtime.internal.j k;
    public final /* synthetic */ DBUser l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(androidx.compose.runtime.internal.j jVar, DBUser dBUser, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.k = jVar;
        this.l = dBUser;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new k(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((k) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:26:0x007b, code lost:
    
        if (r8 == r0) goto L27;
     */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0071  */
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
            r3 = 3
            r4 = 2
            androidx.compose.runtime.internal.j r5 = r7.k
            r6 = 1
            if (r1 == 0) goto L26
            if (r1 == r6) goto L22
            if (r1 == r4) goto L1e
            if (r1 != r3) goto L16
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L7e
        L16:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L69
        L22:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L4b
        L26:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            java.lang.Object r8 = r5.b
            com.quizlet.login.common.interactors.d r8 = (com.quizlet.login.common.interactors.d) r8
            java.lang.Object r8 = r8.b
            com.quizlet.db.b r8 = (com.quizlet.db.b) r8
            android.content.SharedPreferences r8 = r8.a
            java.lang.String r1 = "upgrade_target"
            java.lang.String r8 = r8.getString(r1, r2)
            if (r8 == 0) goto L3c
            goto L87
        L3c:
            java.lang.Object r8 = r5.d
            com.quizlet.data.interactor.achievements.f r8 = (com.quizlet.data.interactor.achievements.f) r8
            r7.j = r6
            com.quizlet.db.data.models.persisted.DBUser r1 = r7.l
            java.lang.Object r8 = r8.j(r1, r7)
            if (r8 != r0) goto L4b
            goto L7d
        L4b:
            java.lang.Boolean r8 = (java.lang.Boolean) r8
            boolean r8 = r8.booleanValue()
            if (r8 == 0) goto L87
            java.lang.Object r8 = r5.g
            com.quizlet.data.repository.folderwithcreatorinclass.e r8 = (com.quizlet.data.repository.folderwithcreatorinclass.e) r8
            r7.j = r4
            com.quizlet.data.interactor.qincentives.b r1 = new com.quizlet.data.interactor.qincentives.b
            r1.<init>(r8, r6, r2)
            java.lang.Object r8 = r8.e
            kotlinx.coroutines.y r8 = (kotlinx.coroutines.AbstractC5040y) r8
            java.lang.Object r8 = kotlinx.coroutines.E.J(r8, r1, r7)
            if (r8 != r0) goto L69
            goto L7d
        L69:
            java.lang.Boolean r8 = (java.lang.Boolean) r8
            boolean r8 = r8.booleanValue()
            if (r8 != 0) goto L87
            java.lang.Object r8 = r5.h
            androidx.work.impl.model.v r8 = (androidx.work.impl.model.v) r8
            r7.j = r3
            java.lang.Object r8 = r8.j(r7)
            if (r8 != r0) goto L7e
        L7d:
            return r0
        L7e:
            java.lang.Boolean r8 = (java.lang.Boolean) r8
            boolean r8 = r8.booleanValue()
            if (r8 != 0) goto L87
            goto L88
        L87:
            r6 = 0
        L88:
            java.lang.Boolean r8 = java.lang.Boolean.valueOf(r6)
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.login.common.interactors.k.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
