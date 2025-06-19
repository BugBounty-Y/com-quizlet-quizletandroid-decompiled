package com.quizlet.login.oldlogin;

import com.quizlet.db.data.models.persisted.DBUser;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ o k;
    public final /* synthetic */ DBUser l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(o oVar, DBUser dBUser, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = oVar;
        this.l = dBUser;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new k(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((k) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:28:0x007a, code lost:
    
        if (r9 == r0) goto L29;
     */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0072  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r9) throws java.lang.Throwable {
        /*
            r8 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r8.j
            com.quizlet.db.data.models.persisted.DBUser r2 = r8.l
            r3 = 3
            r4 = 0
            r5 = 2
            r6 = 1
            com.quizlet.login.oldlogin.o r7 = r8.k
            if (r1 == 0) goto L28
            if (r1 == r6) goto L24
            if (r1 == r5) goto L20
            if (r1 != r3) goto L18
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L7d
        L18:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L20:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L6a
        L24:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L4b
        L28:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            com.quizlet.login.common.interactors.d r9 = r7.k
            java.lang.Object r9 = r9.b
            com.quizlet.db.b r9 = (com.quizlet.db.b) r9
            android.content.SharedPreferences r9 = r9.a
            java.lang.String r1 = "upgrade_target"
            java.lang.String r9 = r9.getString(r1, r4)
            if (r9 == 0) goto L3c
            goto L86
        L3c:
            boolean r9 = r7.r
            if (r9 != 0) goto L86
            r8.j = r6
            com.quizlet.data.interactor.achievements.f r9 = r7.l
            java.lang.Object r9 = r9.j(r2, r8)
            if (r9 != r0) goto L4b
            goto L7c
        L4b:
            java.lang.Boolean r9 = (java.lang.Boolean) r9
            boolean r9 = r9.booleanValue()
            if (r9 == 0) goto L86
            com.quizlet.data.repository.folderwithcreatorinclass.e r9 = r7.o
            r8.j = r5
            r9.getClass()
            com.quizlet.data.interactor.qincentives.b r1 = new com.quizlet.data.interactor.qincentives.b
            r1.<init>(r9, r6, r4)
            java.lang.Object r9 = r9.e
            kotlinx.coroutines.y r9 = (kotlinx.coroutines.AbstractC5040y) r9
            java.lang.Object r9 = kotlinx.coroutines.E.J(r9, r1, r8)
            if (r9 != r0) goto L6a
            goto L7c
        L6a:
            java.lang.Boolean r9 = (java.lang.Boolean) r9
            boolean r9 = r9.booleanValue()
            if (r9 != 0) goto L86
            androidx.work.impl.model.v r9 = r7.p
            r8.j = r3
            java.lang.Object r9 = r9.j(r8)
            if (r9 != r0) goto L7d
        L7c:
            return r0
        L7d:
            java.lang.Boolean r9 = (java.lang.Boolean) r9
            boolean r9 = r9.booleanValue()
            if (r9 != 0) goto L86
            goto L87
        L86:
            r6 = 0
        L87:
            r7.getClass()
            androidx.lifecycle.viewmodel.internal.a r9 = androidx.lifecycle.p0.j(r7)
            com.quizlet.login.oldlogin.n r0 = new com.quizlet.login.oldlogin.n
            r0.<init>(r7, r2, r6, r4)
            kotlinx.coroutines.E.A(r9, r4, r4, r0, r3)
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.login.oldlogin.k.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
