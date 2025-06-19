package androidx.compose.foundation.gestures;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class O extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlin.jvm.internal.J j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ kotlin.jvm.internal.J m;
    public final /* synthetic */ Q n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public O(kotlin.jvm.internal.J j, Q q, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = j;
        this.n = q;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        O o = new O(this.m, this.n, hVar);
        o.l = obj;
        return o;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((O) create((Function1) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x002b  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:20:0x0041 -> B:25:0x0053). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:22:0x004d -> B:24:0x0050). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r7) {
        /*
            r6 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.k
            r2 = 1
            if (r1 == 0) goto L1b
            if (r1 != r2) goto L13
            kotlin.jvm.internal.J r1 = r6.j
            java.lang.Object r3 = r6.l
            kotlin.jvm.functions.Function1 r3 = (kotlin.jvm.functions.Function1) r3
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L50
        L13:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L1b:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Object r7 = r6.l
            kotlin.jvm.functions.Function1 r7 = (kotlin.jvm.functions.Function1) r7
            r3 = r7
        L23:
            kotlin.jvm.internal.J r1 = r6.m
            java.lang.Object r7 = r1.a
            boolean r4 = r7 instanceof androidx.compose.foundation.gestures.C0358x
            if (r4 != 0) goto L56
            boolean r4 = r7 instanceof androidx.compose.foundation.gestures.C0352u
            if (r4 != 0) goto L56
            boolean r4 = r7 instanceof androidx.compose.foundation.gestures.C0354v
            r5 = 0
            if (r4 == 0) goto L37
            androidx.compose.foundation.gestures.v r7 = (androidx.compose.foundation.gestures.C0354v) r7
            goto L38
        L37:
            r7 = r5
        L38:
            if (r7 == 0) goto L3d
            r3.invoke(r7)
        L3d:
            androidx.compose.foundation.gestures.Q r7 = r6.n
            kotlinx.coroutines.channels.h r7 = r7.t
            if (r7 == 0) goto L53
            r6.l = r3
            r6.j = r1
            r6.k = r2
            java.lang.Object r7 = r7.c(r6)
            if (r7 != r0) goto L50
            return r0
        L50:
            r5 = r7
            androidx.compose.foundation.gestures.y r5 = (androidx.compose.foundation.gestures.AbstractC0360y) r5
        L53:
            r1.a = r5
            goto L23
        L56:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.O.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
