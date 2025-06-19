package com.quizlet.features.questiontypes.selfassessment;

import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class g extends i implements Function2 {
    public Throwable j;
    public int k;
    public final /* synthetic */ h l;
    public final /* synthetic */ String m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(h hVar, String str, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.l = hVar;
        this.m = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new g(this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:28:0x006f, code lost:
    
        if (kotlin.Unit.a != r0) goto L34;
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x0085, code lost:
    
        if (kotlin.Unit.a != r0) goto L34;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r10) throws java.lang.Throwable {
        /*
            r9 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r9.k
            r2 = 0
            r3 = 5
            r4 = 4
            r5 = 3
            r6 = 2
            r7 = 1
            com.quizlet.features.questiontypes.selfassessment.h r8 = r9.l
            if (r1 == 0) goto L37
            if (r1 == r7) goto L33
            if (r1 == r6) goto L2b
            if (r1 == r5) goto L27
            if (r1 == r4) goto L27
            if (r1 == r3) goto L20
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r0)
            throw r10
        L20:
            java.lang.Throwable r0 = r9.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L9f
        L27:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L88
        L2b:
            androidx.glance.appwidget.protobuf.Z.e(r10)     // Catch: java.lang.Throwable -> L2f java.io.IOException -> L31
            goto L61
        L2f:
            r10 = move-exception
            goto L8b
        L31:
            r10 = move-exception
            goto L72
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r10)     // Catch: java.lang.Throwable -> L2f java.io.IOException -> L31
            goto L4b
        L37:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            kotlinx.coroutines.flow.s0 r10 = r8.j     // Catch: java.lang.Throwable -> L2f java.io.IOException -> L31
            java.lang.Boolean r1 = java.lang.Boolean.TRUE     // Catch: java.lang.Throwable -> L2f java.io.IOException -> L31
            r9.k = r7     // Catch: java.lang.Throwable -> L2f java.io.IOException -> L31
            r10.getClass()     // Catch: java.lang.Throwable -> L2f java.io.IOException -> L31
            r10.m(r2, r1)     // Catch: java.lang.Throwable -> L2f java.io.IOException -> L31
            kotlin.Unit r10 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L2f java.io.IOException -> L31
            if (r10 != r0) goto L4b
            goto L9d
        L4b:
            com.quizlet.quizletandroid.managers.audio.h r10 = r8.e     // Catch: java.lang.Throwable -> L2f java.io.IOException -> L31
            r10.b(r7)     // Catch: java.lang.Throwable -> L2f java.io.IOException -> L31
            com.quizlet.quizletandroid.managers.audio.h r10 = r8.e     // Catch: java.lang.Throwable -> L2f java.io.IOException -> L31
            java.lang.String r1 = r9.m     // Catch: java.lang.Throwable -> L2f java.io.IOException -> L31
            io.reactivex.rxjava3.internal.operators.completable.a r10 = r10.a(r1)     // Catch: java.lang.Throwable -> L2f java.io.IOException -> L31
            r9.k = r6     // Catch: java.lang.Throwable -> L2f java.io.IOException -> L31
            java.lang.Object r10 = com.google.android.gms.internal.mlkit_vision_camera.I1.a(r10, r9)     // Catch: java.lang.Throwable -> L2f java.io.IOException -> L31
            if (r10 != r0) goto L61
            goto L9d
        L61:
            kotlinx.coroutines.flow.s0 r10 = r8.j
            java.lang.Boolean r1 = java.lang.Boolean.FALSE
            r9.k = r5
            r10.getClass()
            r10.m(r2, r1)
            kotlin.Unit r10 = kotlin.Unit.a
            if (r10 != r0) goto L88
            goto L9d
        L72:
            timber.log.a r1 = timber.log.c.a     // Catch: java.lang.Throwable -> L2f
            r1.e(r10)     // Catch: java.lang.Throwable -> L2f
            kotlinx.coroutines.flow.s0 r10 = r8.j
            java.lang.Boolean r1 = java.lang.Boolean.FALSE
            r9.k = r4
            r10.getClass()
            r10.m(r2, r1)
            kotlin.Unit r10 = kotlin.Unit.a
            if (r10 != r0) goto L88
            goto L9d
        L88:
            kotlin.Unit r10 = kotlin.Unit.a
            return r10
        L8b:
            kotlinx.coroutines.flow.s0 r1 = r8.j
            java.lang.Boolean r4 = java.lang.Boolean.FALSE
            r9.j = r10
            r9.k = r3
            r1.getClass()
            r1.m(r2, r4)
            kotlin.Unit r1 = kotlin.Unit.a
            if (r1 != r0) goto L9e
        L9d:
            return r0
        L9e:
            r0 = r10
        L9f:
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.questiontypes.selfassessment.g.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
