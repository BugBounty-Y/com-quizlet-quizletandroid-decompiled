package kotlinx.coroutines.flow;

import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.internal.AbstractC4998f;

/* renamed from: kotlinx.coroutines.flow.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4986c extends C4988e {
    public final kotlin.coroutines.jvm.internal.i e;

    /* JADX WARN: Multi-variable type inference failed */
    public C4986c(Function2 function2, CoroutineContext coroutineContext, int i, kotlinx.coroutines.channels.a aVar) {
        super(function2, coroutineContext, i, aVar);
        this.e = (kotlin.coroutines.jvm.internal.i) function2;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // kotlinx.coroutines.flow.C4988e, kotlinx.coroutines.flow.internal.AbstractC4998f
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object e(kotlinx.coroutines.channels.u r5, kotlin.coroutines.h r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof kotlinx.coroutines.flow.C4985b
            if (r0 == 0) goto L13
            r0 = r6
            kotlinx.coroutines.flow.b r0 = (kotlinx.coroutines.flow.C4985b) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L1a
        L13:
            kotlinx.coroutines.flow.b r0 = new kotlinx.coroutines.flow.b
            kotlin.coroutines.jvm.internal.c r6 = (kotlin.coroutines.jvm.internal.c) r6
            r0.<init>(r4, r6)
        L1a:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            kotlinx.coroutines.channels.u r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L41
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r5
            r0.m = r3
            java.lang.Object r6 = super.e(r5, r0)
            if (r6 != r1) goto L41
            return r1
        L41:
            kotlinx.coroutines.channels.t r5 = (kotlinx.coroutines.channels.t) r5
            kotlinx.coroutines.channels.h r5 = r5.d
            boolean r5 = r5.z()
            if (r5 == 0) goto L4e
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        L4e:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "'awaitClose { yourCallbackOrListener.cancel() }' should be used in the end of callbackFlow block.\nOtherwise, a callback/listener may leak in case of external cancellation.\nSee callbackFlow API documentation for the details."
            r5.<init>(r6)
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.C4986c.e(kotlinx.coroutines.channels.u, kotlin.coroutines.h):java.lang.Object");
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlinx.coroutines.flow.C4988e, kotlinx.coroutines.flow.internal.AbstractC4998f
    public final AbstractC4998f f(CoroutineContext coroutineContext, int i, kotlinx.coroutines.channels.a aVar) {
        return new C4986c(this.e, coroutineContext, i, aVar);
    }
}
