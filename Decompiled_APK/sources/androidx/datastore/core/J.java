package androidx.datastore.core;

import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class J extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public Object j;
    public int k;
    public final /* synthetic */ P l;
    public final /* synthetic */ CoroutineContext m;
    public final /* synthetic */ Function2 n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public J(P p, CoroutineContext coroutineContext, Function2 function2, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.l = p;
        this.m = coroutineContext;
        this.n = function2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new J(this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((J) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x0053  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0058  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x005d  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0071  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r9) throws java.lang.Throwable {
        /*
            r8 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r8.k
            androidx.datastore.core.P r2 = r8.l
            r3 = 3
            r4 = 2
            r5 = 1
            if (r1 == 0) goto L2b
            if (r1 == r5) goto L27
            if (r1 == r4) goto L1f
            if (r1 != r3) goto L17
            java.lang.Object r0 = r8.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            return r0
        L17:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L1f:
            java.lang.Object r1 = r8.j
            androidx.datastore.core.c r1 = (androidx.datastore.core.C1071c) r1
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L4f
        L27:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L37
        L2b:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r8.k = r5
            java.lang.Object r9 = androidx.datastore.core.P.f(r2, r5, r8)
            if (r9 != r0) goto L37
            goto L6f
        L37:
            r1 = r9
            androidx.datastore.core.c r1 = (androidx.datastore.core.C1071c) r1
            androidx.datastore.core.I r9 = new androidx.datastore.core.I
            kotlin.jvm.functions.Function2 r6 = r8.n
            r7 = 0
            r9.<init>(r6, r1, r7)
            r8.j = r1
            r8.k = r4
            kotlin.coroutines.CoroutineContext r4 = r8.m
            java.lang.Object r9 = kotlinx.coroutines.E.J(r4, r9, r8)
            if (r9 != r0) goto L4f
            goto L6f
        L4f:
            java.lang.Object r4 = r1.b
            if (r4 == 0) goto L58
            int r4 = r4.hashCode()
            goto L59
        L58:
            r4 = 0
        L59:
            int r6 = r1.c
            if (r4 != r6) goto L71
            java.lang.Object r1 = r1.b
            boolean r1 = kotlin.jvm.internal.Intrinsics.b(r1, r9)
            if (r1 != 0) goto L70
            r8.j = r9
            r8.k = r3
            java.lang.Object r1 = r2.j(r9, r5, r8)
            if (r1 != r0) goto L70
        L6f:
            return r0
        L70:
            return r9
        L71:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "Data in DataStore was mutated but DataStore is only compatible with Immutable types."
            r9.<init>(r0)
            throw r9
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.core.J.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
