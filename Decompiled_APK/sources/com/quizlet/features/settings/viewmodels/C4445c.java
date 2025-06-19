package com.quizlet.features.settings.viewmodels;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.settings.viewmodels.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4445c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Object j;
    public int k;
    public final /* synthetic */ C4446d l;
    public final /* synthetic */ String m;
    public final /* synthetic */ String n;
    public final /* synthetic */ String o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4445c(C4446d c4446d, String str, String str2, String str3, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c4446d;
        this.m = str;
        this.n = str2;
        this.o = str3;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4445c(this.l, this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4445c) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x008c  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r12) throws java.lang.Throwable {
        /*
            r11 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r11.k
            com.quizlet.features.settings.viewmodels.d r2 = r11.l
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L27
            if (r1 == r4) goto L1e
            if (r1 != r3) goto L16
            java.lang.Object r0 = r11.j
            androidx.glance.appwidget.protobuf.Z.e(r12)
            r10 = r11
            goto L85
        L16:
            java.lang.IllegalStateException r12 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r12.<init>(r0)
            throw r12
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            kotlin.r r12 = (kotlin.r) r12
            java.lang.Object r12 = r12.a
            r10 = r11
            goto L49
        L27:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            java.util.UUID r12 = java.util.UUID.randomUUID()
            java.lang.String r9 = r12.toString()
            java.lang.String r12 = "toString(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r9, r12)
            com.quizlet.data.repository.qclass.c r5 = r2.d
            r11.k = r4
            java.lang.String r7 = r11.n
            java.lang.String r8 = r11.o
            java.lang.String r6 = r11.m
            r10 = r11
            java.lang.Object r12 = r5.h(r6, r7, r8, r9, r10)
            if (r12 != r0) goto L49
            goto L83
        L49:
            kotlin.p r1 = kotlin.r.b
            boolean r1 = r12 instanceof kotlin.q
            if (r1 != 0) goto L86
            r1 = r12
            kotlin.Unit r1 = (kotlin.Unit) r1
            com.quizlet.usecase.b r1 = r2.g
            kotlin.Unit r4 = kotlin.Unit.a
            com.quizlet.usecase.a r1 = (com.quizlet.usecase.a) r1
            r1.a(r4)
        L5b:
            kotlinx.coroutines.flow.s0 r1 = r2.h
            java.lang.Object r4 = r1.getValue()
            r5 = r4
            com.quizlet.features.settings.data.states.h r5 = (com.quizlet.features.settings.data.states.h) r5
            com.quizlet.features.settings.data.states.f r5 = com.quizlet.features.settings.data.states.f.a
            boolean r1 = r1.k(r4, r5)
            if (r1 == 0) goto L5b
            com.quizlet.features.emailconfirmation.logging.a r1 = r2.f
            com.quizlet.eventlogger.EventLogger r1 = r1.a
            java.lang.String r4 = "user_profile_change_password"
            r1.I(r4)
            kotlinx.coroutines.flow.d0 r1 = r2.b
            kotlin.Unit r2 = kotlin.Unit.a
            r10.j = r12
            r10.k = r3
            java.lang.Object r1 = r1.emit(r2, r11)
            if (r1 != r0) goto L84
        L83:
            return r0
        L84:
            r0 = r12
        L85:
            r12 = r0
        L86:
            java.lang.Throwable r12 = kotlin.r.a(r12)
            if (r12 == 0) goto La0
            com.quizlet.features.settings.composables.x r0 = new com.quizlet.features.settings.composables.x
            java.lang.Class<com.quizlet.features.settings.viewmodels.d> r3 = com.quizlet.features.settings.viewmodels.C4446d.class
            java.lang.String r4 = "handleUpdatePasswordError"
            r1 = 1
            com.quizlet.features.settings.viewmodels.d r2 = r10.l
            java.lang.String r5 = "handleUpdatePasswordError(Lcom/quizlet/api/model/ServerProvidedError;)V"
            r6 = 0
            r7 = 9
            r0.<init>(r1, r2, r3, r4, r5, r6, r7)
            r2.A(r0, r12)
        La0:
            kotlin.Unit r12 = kotlin.Unit.a
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.settings.viewmodels.C4445c.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
