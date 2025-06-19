package com.quizlet.data.repository.metering;

import com.quizlet.generated.enums.P;
import java.io.Serializable;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.J;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Serializable j;
    public J k;
    public int l;
    public /* synthetic */ Object m;
    public final /* synthetic */ j n;
    public final /* synthetic */ long o;
    public final /* synthetic */ Long p;
    public final /* synthetic */ P q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(j jVar, long j, Long l, P p, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.n = jVar;
        this.o = j;
        this.p = l;
        this.q = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        f fVar = new f(this.n, this.o, this.p, this.q, hVar);
        fVar.m = obj;
        return fVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:24:0x00b0  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r18) {
        /*
            r17 = this;
            r0 = r17
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 0
            r4 = 1
            r5 = 2
            r6 = 3
            if (r2 == 0) goto L47
            if (r2 == r4) goto L39
            if (r2 == r5) goto L2a
            if (r2 != r6) goto L22
            java.io.Serializable r1 = r0.j
            com.quizlet.data.model.w0 r1 = (com.quizlet.data.model.InterfaceC4176w0) r1
            java.lang.Object r2 = r0.m
            kotlinx.coroutines.C r2 = (kotlinx.coroutines.C) r2
            androidx.glance.appwidget.protobuf.Z.e(r18)
            r7 = r2
            r2 = r18
            goto Lb1
        L22:
            java.lang.IllegalStateException r1 = new java.lang.IllegalStateException
            java.lang.String r2 = "call to 'resume' before 'invoke' with coroutine"
            r1.<init>(r2)
            throw r1
        L2a:
            java.io.Serializable r2 = r0.j
            kotlin.jvm.internal.J r2 = (kotlin.jvm.internal.J) r2
            java.lang.Object r4 = r0.m
            kotlinx.coroutines.C r4 = (kotlinx.coroutines.C) r4
            androidx.glance.appwidget.protobuf.Z.e(r18)
            r7 = r4
            r4 = r18
            goto L9d
        L39:
            kotlin.jvm.internal.J r2 = r0.k
            java.io.Serializable r4 = r0.j
            kotlin.jvm.internal.J r4 = (kotlin.jvm.internal.J) r4
            java.lang.Object r7 = r0.m
            kotlinx.coroutines.C r7 = (kotlinx.coroutines.C) r7
            androidx.glance.appwidget.protobuf.Z.e(r18)
            goto L8a
        L47:
            androidx.glance.appwidget.protobuf.Z.e(r18)
            java.lang.Object r2 = r0.m
            r7 = r2
            kotlinx.coroutines.C r7 = (kotlinx.coroutines.C) r7
            kotlin.jvm.internal.J r9 = new kotlin.jvm.internal.J
            r9.<init>()
            kotlin.jvm.internal.J r10 = new kotlin.jvm.internal.J
            r10.<init>()
            com.quizlet.data.repository.metering.d r8 = new com.quizlet.data.repository.metering.d
            long r12 = r0.o
            java.lang.Long r14 = r0.p
            com.quizlet.data.repository.metering.j r11 = r0.n
            com.quizlet.generated.enums.P r15 = r0.q
            r16 = 0
            r8.<init>(r9, r10, r11, r12, r14, r15, r16)
            r0.m = r7
            r0.j = r9
            r0.k = r10
            r0.l = r4
            kotlinx.coroutines.z0 r2 = new kotlinx.coroutines.z0
            kotlin.coroutines.CoroutineContext r11 = r0.getContext()
            r12 = 0
            r2.<init>(r11, r0, r12)
            java.lang.Object r2 = com.google.android.gms.internal.mlkit_vision_camera.H1.c(r2, r4, r2, r8)
            if (r2 != r1) goto L85
            java.lang.String r4 = "frame"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r4)
        L85:
            if (r2 != r1) goto L88
            goto Laf
        L88:
            r4 = r9
            r2 = r10
        L8a:
            java.lang.Object r4 = r4.a
            kotlinx.coroutines.H r4 = (kotlinx.coroutines.H) r4
            r0.m = r7
            r0.j = r2
            r0.k = r3
            r0.l = r5
            java.lang.Object r4 = r4.Y(r0)
            if (r4 != r1) goto L9d
            goto Laf
        L9d:
            com.quizlet.data.model.w0 r4 = (com.quizlet.data.model.InterfaceC4176w0) r4
            java.lang.Object r2 = r2.a
            kotlinx.coroutines.H r2 = (kotlinx.coroutines.H) r2
            r0.m = r7
            r0.j = r4
            r0.l = r6
            java.lang.Object r2 = r2.Y(r0)
            if (r2 != r1) goto Lb0
        Laf:
            return r1
        Lb0:
            r1 = r4
        Lb1:
            com.quizlet.data.model.w0 r2 = (com.quizlet.data.model.InterfaceC4176w0) r2
            kotlinx.coroutines.A0 r4 = kotlinx.coroutines.E.e()
            com.quizlet.data.repository.metering.e r6 = new com.quizlet.data.repository.metering.e
            com.quizlet.data.repository.metering.j r8 = r0.n
            r6.<init>(r8, r2, r1, r3)
            kotlinx.coroutines.E.A(r7, r4, r3, r6, r5)
            r8.getClass()
            com.quizlet.data.model.w0 r1 = com.quizlet.data.repository.metering.j.d(r2, r1)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.metering.f.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
