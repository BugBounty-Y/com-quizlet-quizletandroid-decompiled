package androidx.compose.foundation;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class r0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ s0 k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r0(s0 s0Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = s0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new r0(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((r0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
        return kotlin.coroutines.intrinsics.a.a;
    }

    /* JADX WARN: Code restructure failed: missing block: B:19:0x0048, code lost:
    
        if (androidx.compose.runtime.C0776c.r(getContext()).P(new androidx.compose.animation.core.C0268t0(1, r8), r7) == r0) goto L20;
     */
    /* JADX WARN: Path cross not found for [B:13:0x0025, B:16:0x002e], limit reached: 23 */
    /* JADX WARN: Path cross not found for [B:16:0x002e, B:13:0x0025], limit reached: 23 */
    /* JADX WARN: Removed duplicated region for block: B:11:0x0021  */
    /* JADX WARN: Removed duplicated region for block: B:13:0x0025  */
    /* JADX WARN: Removed duplicated region for block: B:18:0x0032  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:17:0x0030 -> B:11:0x0021). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:19:0x0048 -> B:21:0x004b). Please report as a decompilation issue!!! */
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
            androidx.compose.foundation.s0 r4 = r7.k
            if (r1 == 0) goto L1e
            if (r1 == r3) goto L1a
            if (r1 != r2) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L4b
        L12:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L2e
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r8)
        L21:
            kotlinx.coroutines.channels.h r8 = r4.x
            if (r8 == 0) goto L2e
            r7.j = r3
            java.lang.Object r8 = r8.c(r7)
            if (r8 != r0) goto L2e
            goto L4a
        L2e:
            androidx.compose.foundation.D0 r8 = r4.s
            if (r8 == 0) goto L21
            androidx.compose.foundation.t r8 = androidx.compose.foundation.C0476t.d
            r7.j = r2
            kotlin.coroutines.CoroutineContext r1 = r7.getContext()
            androidx.compose.runtime.W r1 = androidx.compose.runtime.C0776c.r(r1)
            androidx.compose.animation.core.t0 r5 = new androidx.compose.animation.core.t0
            r6 = 1
            r5.<init>(r6, r8)
            java.lang.Object r8 = r1.P(r5, r7)
            if (r8 != r0) goto L4b
        L4a:
            return r0
        L4b:
            androidx.compose.foundation.D0 r8 = r4.s
            if (r8 == 0) goto L21
            androidx.compose.foundation.F0 r8 = (androidx.compose.foundation.F0) r8
            r8.d()
            goto L21
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.r0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
