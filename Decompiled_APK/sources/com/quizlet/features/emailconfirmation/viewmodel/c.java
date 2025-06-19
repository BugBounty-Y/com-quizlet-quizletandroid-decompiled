package com.quizlet.features.emailconfirmation.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ f k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(f fVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new c(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:33:0x008d, code lost:
    
        if (r9.emit(r1, r8) != r0) goto L35;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r9) {
        /*
            r8 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r8.j
            r2 = 3
            r3 = 0
            r4 = 2
            r5 = 1
            com.quizlet.features.emailconfirmation.viewmodel.f r6 = r8.k
            if (r1 == 0) goto L28
            if (r1 == r5) goto L24
            if (r1 == r4) goto L1f
            if (r1 != r2) goto L17
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L90
        L17:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L1f:
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Throwable -> L83
            goto L90
        L24:
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Throwable -> L83
            goto L48
        L28:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            com.google.firebase.crashlytics.internal.common.j r9 = r6.c     // Catch: java.lang.Throwable -> L83
            r8.j = r5     // Catch: java.lang.Throwable -> L83
            java.lang.Object r9 = r9.b     // Catch: java.lang.Throwable -> L83
            com.quizlet.remote.model.user.emailconfirmation.c r9 = (com.quizlet.remote.model.user.emailconfirmation.c) r9     // Catch: java.lang.Throwable -> L83
            com.quizlet.remote.model.user.emailconfirmation.b r1 = new com.quizlet.remote.model.user.emailconfirmation.b     // Catch: java.lang.Throwable -> L83
            r1.<init>(r9, r3)     // Catch: java.lang.Throwable -> L83
            com.quizlet.remote.model.user.emailconfirmation.a r7 = new com.quizlet.remote.model.user.emailconfirmation.a     // Catch: java.lang.Throwable -> L83
            r7.<init>(r9, r1, r3)     // Catch: java.lang.Throwable -> L83
            java.lang.Object r9 = r9.b     // Catch: java.lang.Throwable -> L83
            kotlinx.coroutines.y r9 = (kotlinx.coroutines.AbstractC5040y) r9     // Catch: java.lang.Throwable -> L83
            java.lang.Object r9 = kotlinx.coroutines.E.J(r9, r7, r8)     // Catch: java.lang.Throwable -> L83
            if (r9 != r0) goto L48
            goto L8f
        L48:
            com.quizlet.data.model.u1 r9 = (com.quizlet.data.model.EnumC4171u1) r9     // Catch: java.lang.Throwable -> L83
            int r9 = r9.ordinal()     // Catch: java.lang.Throwable -> L83
            if (r9 == 0) goto L7b
            if (r9 == r5) goto L6e
            if (r9 != r4) goto L68
            kotlinx.coroutines.flow.s0 r9 = r6.f     // Catch: java.lang.Throwable -> L83
        L56:
            java.lang.Object r1 = r9.getValue()     // Catch: java.lang.Throwable -> L83
            r4 = r1
            com.quizlet.features.emailconfirmation.data.states.a r4 = (com.quizlet.features.emailconfirmation.data.states.a) r4     // Catch: java.lang.Throwable -> L83
            com.quizlet.features.emailconfirmation.data.states.a r4 = com.quizlet.features.emailconfirmation.data.states.a.a(r4, r3, r3, r2)     // Catch: java.lang.Throwable -> L83
            boolean r1 = r9.k(r1, r4)     // Catch: java.lang.Throwable -> L83
            if (r1 == 0) goto L56
            goto L90
        L68:
            kotlin.NoWhenBranchMatchedException r9 = new kotlin.NoWhenBranchMatchedException     // Catch: java.lang.Throwable -> L83
            r9.<init>()     // Catch: java.lang.Throwable -> L83
            throw r9     // Catch: java.lang.Throwable -> L83
        L6e:
            kotlinx.coroutines.flow.d0 r9 = r6.h     // Catch: java.lang.Throwable -> L83
            java.lang.Boolean r1 = java.lang.Boolean.TRUE     // Catch: java.lang.Throwable -> L83
            r8.j = r4     // Catch: java.lang.Throwable -> L83
            java.lang.Object r9 = r9.emit(r1, r8)     // Catch: java.lang.Throwable -> L83
            if (r9 != r0) goto L90
            goto L8f
        L7b:
            kotlinx.coroutines.flow.d0 r9 = r6.g     // Catch: java.lang.Throwable -> L83
            com.quizlet.features.emailconfirmation.data.events.a r1 = com.quizlet.features.emailconfirmation.data.events.a.b     // Catch: java.lang.Throwable -> L83
            r9.h(r1)     // Catch: java.lang.Throwable -> L83
            goto L90
        L83:
            kotlinx.coroutines.flow.d0 r9 = r6.h
            java.lang.Boolean r1 = java.lang.Boolean.FALSE
            r8.j = r2
            java.lang.Object r9 = r9.emit(r1, r8)
            if (r9 != r0) goto L90
        L8f:
            return r0
        L90:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.emailconfirmation.viewmodel.c.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
