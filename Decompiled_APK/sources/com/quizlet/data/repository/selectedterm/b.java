package com.quizlet.data.repository.selectedterm;

import com.quizlet.data.model.J0;
import com.quizlet.data.model.N;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class b extends i implements Function2 {
    public Object j;
    public N k;
    public long l;
    public long m;
    public int n;
    public final /* synthetic */ f o;
    public final /* synthetic */ long p;
    public final /* synthetic */ long q;
    public final /* synthetic */ J0 r;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(f fVar, long j, long j2, J0 j0, h hVar) {
        super(2, hVar);
        this.o = fVar;
        this.p = j;
        this.q = j2;
        this.r = j0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.o, this.p, this.q, this.r, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:24:0x0089  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x009b  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r13) {
        /*
            r12 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r12.n
            com.quizlet.data.repository.selectedterm.f r2 = r12.o
            r3 = 3
            r4 = 2
            r5 = 1
            if (r1 == 0) goto L3d
            if (r1 == r5) goto L34
            if (r1 == r4) goto L22
            if (r1 != r3) goto L1a
            java.lang.Object r0 = r12.j
            com.quizlet.data.model.N r0 = (com.quizlet.data.model.N) r0
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L8b
        L1a:
            java.lang.IllegalStateException r13 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r13.<init>(r0)
            throw r13
        L22:
            long r4 = r12.m
            long r6 = r12.l
            com.quizlet.data.model.N r1 = r12.k
            java.lang.Object r8 = r12.j
            com.quizlet.data.repository.selectedterm.f r8 = (com.quizlet.data.repository.selectedterm.f) r8
            androidx.glance.appwidget.protobuf.Z.e(r13)
            r10 = r12
            r13 = r1
            r1 = r8
            r8 = r4
            goto L79
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            kotlin.r r13 = (kotlin.r) r13
            java.lang.Object r13 = r13.a
            r10 = r12
            goto L54
        L3d:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            r13 = r5
            com.quizlet.data.interactor.set.c r5 = r2.a
            r12.n = r13
            long r8 = r12.q
            com.quizlet.data.model.J0 r10 = r12.r
            long r6 = r12.p
            r11 = r12
            java.lang.Object r13 = r5.m(r6, r8, r10, r11)
            r10 = r11
            if (r13 != r0) goto L54
            goto L88
        L54:
            kotlin.p r1 = kotlin.r.b
            boolean r1 = r13 instanceof kotlin.q
            if (r1 != 0) goto L95
            com.quizlet.data.model.N r13 = (com.quizlet.data.model.N) r13
            com.quizlet.data.repository.login.a r1 = r2.b
            java.lang.Object r5 = r13.a
            java.util.List r5 = (java.util.List) r5
            r10.j = r2
            r10.k = r13
            long r6 = r10.p
            r10.l = r6
            long r8 = r10.q
            r10.m = r8
            r10.n = r4
            r4 = 0
            java.io.Serializable r1 = r1.m(r5, r4, r12)
            if (r1 != r0) goto L78
            goto L88
        L78:
            r1 = r2
        L79:
            com.quizlet.data.repository.login.a r5 = r1.b
            r10.j = r13
            r1 = 0
            r10.k = r1
            r10.n = r3
            java.io.Serializable r1 = r5.f(r6, r8, r10)
            if (r1 != r0) goto L89
        L88:
            return r0
        L89:
            r0 = r13
            r13 = r1
        L8b:
            com.quizlet.data.model.J0 r0 = r0.b
            com.quizlet.data.model.N r1 = new com.quizlet.data.model.N
            r1.<init>(r13, r0)
            kotlin.p r13 = kotlin.r.b
            r13 = r1
        L95:
            java.lang.Throwable r0 = kotlin.r.a(r13)
            if (r0 == 0) goto La2
            org.slf4j.b r1 = r2.d
            java.lang.String r2 = "Error retrieving selected terms from remote"
            r1.c(r2, r0)
        La2:
            kotlin.r r0 = new kotlin.r
            r0.<init>(r13)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.selectedterm.b.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
