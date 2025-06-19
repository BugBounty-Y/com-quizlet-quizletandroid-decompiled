package com.quizlet.data.repository.selectedterm;

import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class e extends i implements Function2 {
    public int j;
    public final /* synthetic */ f k;
    public final /* synthetic */ long l;
    public final /* synthetic */ long m;
    public final /* synthetic */ long n;
    public final /* synthetic */ boolean o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(f fVar, long j, long j2, long j3, boolean z, h hVar) {
        super(2, hVar);
        this.k = fVar;
        this.l = j;
        this.m = j2;
        this.n = j3;
        this.o = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new e(this.k, this.l, this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:33:0x0094, code lost:
    
        if (r0 != r10) goto L35;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r25) {
        /*
            r24 = this;
            r9 = r24
            kotlin.coroutines.intrinsics.a r10 = kotlin.coroutines.intrinsics.a.a
            int r0 = r9.j
            com.quizlet.data.repository.selectedterm.f r1 = r9.k
            r11 = 3
            r12 = 2
            r13 = 1
            org.slf4j.b r14 = r1.d
            com.quizlet.data.repository.login.a r15 = r1.b
            if (r0 == 0) goto L37
            if (r0 == r13) goto L31
            if (r0 == r12) goto L29
            if (r0 != r11) goto L21
            androidx.glance.appwidget.protobuf.Z.e(r25)     // Catch: java.lang.Exception -> L1e
            r0 = r25
            goto L97
        L1e:
            r0 = move-exception
            goto L9a
        L21:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r1 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r1)
            throw r0
        L29:
            androidx.glance.appwidget.protobuf.Z.e(r25)     // Catch: java.lang.Exception -> L2f
            r0 = r25
            goto L5a
        L2f:
            r0 = move-exception
            goto L5d
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r25)     // Catch: java.lang.Exception -> L2f
            r0 = r25
            goto L4e
        L37:
            androidx.glance.appwidget.protobuf.Z.e(r25)
            com.quizlet.data.interactor.set.c r0 = r1.a     // Catch: java.lang.Exception -> L2f
            long r1 = r9.l     // Catch: java.lang.Exception -> L2f
            long r3 = r9.m     // Catch: java.lang.Exception -> L2f
            long r5 = r9.n     // Catch: java.lang.Exception -> L2f
            boolean r8 = r9.o     // Catch: java.lang.Exception -> L2f
            r9.j = r13     // Catch: java.lang.Exception -> L2f
            r7 = 3
            java.io.Serializable r0 = r0.q(r1, r3, r5, r7, r8, r9)     // Catch: java.lang.Exception -> L2f
            if (r0 != r10) goto L4e
            goto L96
        L4e:
            java.util.List r0 = (java.util.List) r0     // Catch: java.lang.Exception -> L2f
            r9.j = r12     // Catch: java.lang.Exception -> L2f
            r1 = 0
            java.io.Serializable r0 = r15.m(r0, r1, r9)     // Catch: java.lang.Exception -> L2f
            if (r0 != r10) goto L5a
            goto L96
        L5a:
            java.util.List r0 = (java.util.List) r0     // Catch: java.lang.Exception -> L2f
            return r0
        L5d:
            java.lang.String r1 = "Failed to select term remotely"
            r14.l(r1, r0)
            long r3 = r9.l     // Catch: java.lang.Exception -> L1e
            long r0 = r9.m     // Catch: java.lang.Exception -> L1e
            long r5 = r9.n     // Catch: java.lang.Exception -> L1e
            boolean r2 = r9.o     // Catch: java.lang.Exception -> L1e
            r9.j = r11     // Catch: java.lang.Exception -> L1e
            if (r2 == 0) goto L7c
            com.quizlet.data.model.E1 r16 = new com.quizlet.data.model.E1     // Catch: java.lang.Exception -> L1e
            r21 = 3
            r22 = r0
            r17 = r3
            r19 = r5
            r16.<init>(r17, r19, r21, r22)     // Catch: java.lang.Exception -> L1e
            goto L8c
        L7c:
            r17 = r3
            r19 = r5
            com.quizlet.data.model.p2 r2 = new com.quizlet.data.model.p2     // Catch: java.lang.Exception -> L1e
            r7 = 1
            r3 = r17
            r5 = r19
            r2.<init>(r3, r5, r7)     // Catch: java.lang.Exception -> L1e
            r16 = r2
        L8c:
            java.util.List r0 = kotlin.collections.A.b(r16)     // Catch: java.lang.Exception -> L1e
            java.io.Serializable r0 = r15.m(r0, r13, r9)     // Catch: java.lang.Exception -> L1e
            if (r0 != r10) goto L97
        L96:
            return r10
        L97:
            java.util.List r0 = (java.util.List) r0     // Catch: java.lang.Exception -> L1e
            goto La1
        L9a:
            java.lang.String r1 = "Failed to save selected term locally"
            r14.l(r1, r0)
            kotlin.collections.K r0 = kotlin.collections.K.a
        La1:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.selectedterm.e.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
