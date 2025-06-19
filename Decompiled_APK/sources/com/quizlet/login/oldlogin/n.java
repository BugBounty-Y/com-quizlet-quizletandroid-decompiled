package com.quizlet.login.oldlogin;

import com.quizlet.db.data.models.persisted.DBUser;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class n extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ o k;
    public final /* synthetic */ DBUser l;
    public final /* synthetic */ boolean m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(o oVar, DBUser dBUser, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = oVar;
        this.l = dBUser;
        this.m = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new n(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((n) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x003a, code lost:
    
        if (r8 == r0) goto L15;
     */
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
            r2 = 2
            r3 = 1
            com.quizlet.login.oldlogin.o r4 = r7.k
            if (r1 == 0) goto L1e
            if (r1 == r3) goto L1a
            if (r1 != r2) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L3d
        L12:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L32
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.google.firebase.crashlytics.internal.common.j r8 = r4.q
            com.quizlet.db.data.models.persisted.DBUser r1 = r7.l
            long r5 = r1.getId()
            r7.j = r3
            java.lang.Object r8 = r8.e(r5, r7)
            if (r8 != r0) goto L32
            goto L3c
        L32:
            com.google.firebase.crashlytics.internal.settings.b r8 = r4.m
            r7.j = r2
            java.lang.Object r8 = r8.d(r7)
            if (r8 != r0) goto L3d
        L3c:
            return r0
        L3d:
            java.lang.Boolean r8 = (java.lang.Boolean) r8
            boolean r8 = r8.booleanValue()
            boolean r0 = r7.m
            if (r0 == 0) goto L52
            androidx.lifecycle.X r0 = r4.t
            com.quizlet.login.oldlogin.f r1 = new com.quizlet.login.oldlogin.f
            r1.<init>(r8)
            r0.j(r1)
            goto L5c
        L52:
            androidx.lifecycle.X r0 = r4.t
            com.quizlet.login.oldlogin.d r1 = new com.quizlet.login.oldlogin.d
            r1.<init>(r8)
            r0.j(r1)
        L5c:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.login.oldlogin.n.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
