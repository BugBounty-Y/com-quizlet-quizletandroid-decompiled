package com.quizlet.data.interactor.achievements;

import com.google.firebase.messaging.p;
import java.time.LocalDate;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class m extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Object j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ p m;
    public final /* synthetic */ boolean n;
    public final /* synthetic */ LocalDate o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(p pVar, LocalDate localDate, kotlin.coroutines.h hVar, boolean z) {
        super(2, hVar);
        this.m = pVar;
        this.n = z;
        this.o = localDate;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        m mVar = new m(this.m, this.o, hVar, this.n);
        mVar.l = obj;
        return mVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((m) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x0098  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r13) throws java.lang.Throwable {
        /*
            r12 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r12.k
            r2 = 3
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L3c
            if (r1 == r4) goto L30
            if (r1 == r3) goto L24
            if (r1 != r2) goto L1c
            java.lang.Object r0 = r12.j
            com.quizlet.data.model.h2 r0 = (com.quizlet.data.model.h2) r0
            java.lang.Object r1 = r12.l
            com.quizlet.data.model.g r1 = (com.quizlet.data.model.AbstractC4128g) r1
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L9a
        L1c:
            java.lang.IllegalStateException r13 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r13.<init>(r0)
            throw r13
        L24:
            java.lang.Object r1 = r12.j
            com.quizlet.data.model.g r1 = (com.quizlet.data.model.AbstractC4128g) r1
            java.lang.Object r3 = r12.l
            kotlinx.coroutines.H r3 = (kotlinx.coroutines.H) r3
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L89
        L30:
            java.lang.Object r1 = r12.j
            kotlinx.coroutines.H r1 = (kotlinx.coroutines.H) r1
            java.lang.Object r4 = r12.l
            kotlinx.coroutines.H r4 = (kotlinx.coroutines.H) r4
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L76
        L3c:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            java.lang.Object r13 = r12.l
            kotlinx.coroutines.C r13 = (kotlinx.coroutines.C) r13
            com.quizlet.data.interactor.achievements.k r1 = new com.quizlet.data.interactor.achievements.k
            com.google.firebase.messaging.p r5 = r12.m
            boolean r6 = r12.n
            r7 = 0
            r1.<init>(r5, r6, r7)
            kotlinx.coroutines.I r1 = kotlinx.coroutines.E.f(r13, r7, r1, r2)
            com.quizlet.data.interactor.achievements.l r8 = new com.quizlet.data.interactor.achievements.l
            r8.<init>(r5, r6, r7)
            kotlinx.coroutines.I r8 = kotlinx.coroutines.E.f(r13, r7, r8, r2)
            com.quizlet.data.interactor.achievements.j r9 = new com.quizlet.data.interactor.achievements.j
            java.time.LocalDate r10 = r12.o
            r9.<init>(r5, r10, r7, r6)
            kotlinx.coroutines.I r13 = kotlinx.coroutines.E.f(r13, r7, r9, r2)
            r12.l = r8
            r12.j = r13
            r12.k = r4
            java.lang.Object r1 = r1.w(r12)
            if (r1 != r0) goto L72
            goto L97
        L72:
            r4 = r1
            r1 = r13
            r13 = r4
            r4 = r8
        L76:
            com.quizlet.data.model.g r13 = (com.quizlet.data.model.AbstractC4128g) r13
            r12.l = r1
            r12.j = r13
            r12.k = r3
            java.lang.Object r3 = r4.Y(r12)
            if (r3 != r0) goto L85
            goto L97
        L85:
            r11 = r1
            r1 = r13
            r13 = r3
            r3 = r11
        L89:
            com.quizlet.data.model.h2 r13 = (com.quizlet.data.model.h2) r13
            r12.l = r1
            r12.j = r13
            r12.k = r2
            java.lang.Object r2 = r3.Y(r12)
            if (r2 != r0) goto L98
        L97:
            return r0
        L98:
            r0 = r13
            r13 = r2
        L9a:
            com.quizlet.data.model.s r13 = (com.quizlet.data.model.AbstractC4163s) r13
            com.quizlet.data.interactor.achievements.g r2 = new com.quizlet.data.interactor.achievements.g
            r2.<init>(r1, r0, r13)
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.achievements.m.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
