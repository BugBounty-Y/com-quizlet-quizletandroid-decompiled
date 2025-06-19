package kotlinx.coroutines.flow.internal;

import androidx.datastore.core.C1087t;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C5027k0;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes3.dex */
public final class w extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public C5027k0 j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ C1087t m;
    public final /* synthetic */ com.quizlet.analytics.marketing.appsflyer.d n;
    public final /* synthetic */ InterfaceC5002j o;
    public final /* synthetic */ com.quizlet.qutils.coroutines.a p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public w(C1087t c1087t, com.quizlet.analytics.marketing.appsflyer.d dVar, InterfaceC5002j interfaceC5002j, com.quizlet.qutils.coroutines.a aVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = c1087t;
        this.n = dVar;
        this.o = interfaceC5002j;
        this.p = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        w wVar = new w(this.m, this.n, this.o, this.p, hVar);
        wVar.l = obj;
        return wVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((w) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:31:0x008b A[Catch: all -> 0x0015, TRY_ENTER, TRY_LEAVE, TryCatch #1 {all -> 0x0015, blocks: (B:6:0x0011, B:26:0x0083, B:31:0x008b), top: B:34:0x0006 }] */
    /* JADX WARN: Type inference failed for: r3v0 */
    /* JADX WARN: Type inference failed for: r3v1, types: [kotlinx.coroutines.channels.w] */
    /* JADX WARN: Type inference failed for: r3v2 */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r15) throws java.lang.Throwable {
        /*
            r14 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r14.k
            r2 = 0
            r3 = 1
            if (r1 == 0) goto L25
            if (r1 != r3) goto L1d
            kotlinx.coroutines.k0 r1 = r14.j
            java.lang.Object r0 = r14.l
            r3 = r0
            kotlinx.coroutines.channels.w r3 = (kotlinx.coroutines.channels.w) r3
            androidx.glance.appwidget.protobuf.Z.e(r15)     // Catch: java.lang.Throwable -> L15 kotlinx.coroutines.flow.internal.AbortFlowException -> L19
            goto L74
        L15:
            r0 = move-exception
            r15 = r0
            goto L8c
        L19:
            r0 = move-exception
            r15 = r0
            goto L83
        L1d:
            java.lang.IllegalStateException r15 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r15.<init>(r0)
            throw r15
        L25:
            androidx.glance.appwidget.protobuf.Z.e(r15)
            java.lang.Object r15 = r14.l
            kotlinx.coroutines.C r15 = (kotlinx.coroutines.C) r15
            kotlinx.coroutines.flow.internal.v r1 = new kotlinx.coroutines.flow.internal.v
            androidx.datastore.core.t r4 = r14.m
            r1.<init>(r4, r2)
            kotlinx.coroutines.channels.t r9 = com.google.android.gms.internal.mlkit_vision_camera.F1.b(r15, r1)
            kotlinx.coroutines.k0 r12 = kotlinx.coroutines.E.d()
            io.ktor.client.engine.k r1 = new io.ktor.client.engine.k
            r4 = 1
            r1.<init>(r12, r4)
            r9.n(r1)
            kotlin.coroutines.CoroutineContext r7 = r15.getCoroutineContext()     // Catch: java.lang.Throwable -> L7d kotlinx.coroutines.flow.internal.AbortFlowException -> L80
            java.lang.Object r8 = kotlinx.coroutines.internal.t.b(r7)     // Catch: java.lang.Throwable -> L7d kotlinx.coroutines.flow.internal.AbortFlowException -> L80
            kotlin.coroutines.CoroutineContext r15 = r15.getCoroutineContext()     // Catch: java.lang.Throwable -> L7d kotlinx.coroutines.flow.internal.AbortFlowException -> L80
            kotlin.coroutines.CoroutineContext r15 = r15.plus(r12)     // Catch: java.lang.Throwable -> L7d kotlinx.coroutines.flow.internal.AbortFlowException -> L80
            kotlin.Unit r1 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L7d kotlinx.coroutines.flow.internal.AbortFlowException -> L80
            kotlinx.coroutines.flow.internal.t r5 = new kotlinx.coroutines.flow.internal.t     // Catch: java.lang.Throwable -> L7d kotlinx.coroutines.flow.internal.AbortFlowException -> L80
            com.quizlet.analytics.marketing.appsflyer.d r6 = r14.n     // Catch: java.lang.Throwable -> L7d kotlinx.coroutines.flow.internal.AbortFlowException -> L80
            kotlinx.coroutines.flow.j r10 = r14.o     // Catch: java.lang.Throwable -> L7d kotlinx.coroutines.flow.internal.AbortFlowException -> L80
            com.quizlet.qutils.coroutines.a r11 = r14.p     // Catch: java.lang.Throwable -> L7d kotlinx.coroutines.flow.internal.AbortFlowException -> L80
            r13 = 0
            r5.<init>(r6, r7, r8, r9, r10, r11, r12, r13)     // Catch: java.lang.Throwable -> L7d kotlinx.coroutines.flow.internal.AbortFlowException -> L80
            r14.l = r9     // Catch: java.lang.Throwable -> L7d kotlinx.coroutines.flow.internal.AbortFlowException -> L80
            r14.j = r12     // Catch: java.lang.Throwable -> L7d kotlinx.coroutines.flow.internal.AbortFlowException -> L80
            r14.k = r3     // Catch: java.lang.Throwable -> L7d kotlinx.coroutines.flow.internal.AbortFlowException -> L80
            java.lang.Object r3 = kotlinx.coroutines.internal.t.b(r15)     // Catch: java.lang.Throwable -> L7d kotlinx.coroutines.flow.internal.AbortFlowException -> L80
            java.lang.Object r15 = kotlinx.coroutines.flow.internal.AbstractC4994b.c(r15, r1, r3, r5, r14)     // Catch: java.lang.Throwable -> L7d kotlinx.coroutines.flow.internal.AbortFlowException -> L80
            if (r15 != r0) goto L73
            return r0
        L73:
            r3 = r9
        L74:
            r3.j(r2)
            goto L88
        L78:
            r3 = r9
            goto L8c
        L7a:
            r3 = r9
            r1 = r12
            goto L83
        L7d:
            r0 = move-exception
            r15 = r0
            goto L78
        L80:
            r0 = move-exception
            r15 = r0
            goto L7a
        L83:
            java.lang.Object r0 = r15.a     // Catch: java.lang.Throwable -> L15
            if (r0 != r1) goto L8b
            goto L74
        L88:
            kotlin.Unit r15 = kotlin.Unit.a
            return r15
        L8b:
            throw r15     // Catch: java.lang.Throwable -> L15
        L8c:
            r3.j(r2)
            throw r15
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.internal.w.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
