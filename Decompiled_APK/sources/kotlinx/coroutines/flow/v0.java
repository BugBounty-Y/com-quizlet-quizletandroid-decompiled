package kotlinx.coroutines.flow;

import androidx.paging.C1315g;

/* loaded from: classes3.dex */
public final class v0 implements InterfaceC5002j {
    public final InterfaceC5002j a;
    public final C1315g b;

    public v0(InterfaceC5002j interfaceC5002j, C1315g c1315g) {
        this.a = interfaceC5002j;
        this.b = c1315g;
    }

    /* JADX WARN: Code restructure failed: missing block: B:28:0x0070, code lost:
    
        if (((kotlinx.coroutines.flow.v0) r7).a(r0) == r1) goto L29;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r2v0, types: [int] */
    /* JADX WARN: Type inference failed for: r2v1, types: [kotlin.coroutines.jvm.internal.c] */
    /* JADX WARN: Type inference failed for: r2v4, types: [boolean] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(kotlin.coroutines.jvm.internal.c r7) {
        /*
            r6 = this;
            boolean r0 = r7 instanceof kotlinx.coroutines.flow.u0
            if (r0 == 0) goto L13
            r0 = r7
            kotlinx.coroutines.flow.u0 r0 = (kotlinx.coroutines.flow.u0) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            kotlinx.coroutines.flow.u0 r0 = new kotlinx.coroutines.flow.u0
            r0.<init>(r6, r7)
        L18:
            java.lang.Object r7 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3c
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L73
        L2a:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L32:
            kotlinx.coroutines.flow.internal.C r2 = r0.k
            kotlinx.coroutines.flow.v0 r4 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)     // Catch: java.lang.Throwable -> L3a
            goto L5a
        L3a:
            r7 = move-exception
            goto L79
        L3c:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlinx.coroutines.flow.internal.C r2 = new kotlinx.coroutines.flow.internal.C
            kotlinx.coroutines.flow.j r7 = r6.a
            kotlin.coroutines.CoroutineContext r5 = r0.getContext()
            r2.<init>(r7, r5)
            androidx.paging.g r7 = r6.b     // Catch: java.lang.Throwable -> L3a
            r0.j = r6     // Catch: java.lang.Throwable -> L3a
            r0.k = r2     // Catch: java.lang.Throwable -> L3a
            r0.n = r4     // Catch: java.lang.Throwable -> L3a
            java.lang.Object r7 = r7.invoke(r2, r0)     // Catch: java.lang.Throwable -> L3a
            if (r7 != r1) goto L59
            goto L72
        L59:
            r4 = r6
        L5a:
            r2.releaseIntercepted()
            kotlinx.coroutines.flow.j r7 = r4.a
            boolean r2 = r7 instanceof kotlinx.coroutines.flow.v0
            if (r2 == 0) goto L76
            kotlinx.coroutines.flow.v0 r7 = (kotlinx.coroutines.flow.v0) r7
            r2 = 0
            r0.j = r2
            r0.k = r2
            r0.n = r3
            java.lang.Object r7 = r7.a(r0)
            if (r7 != r1) goto L73
        L72:
            return r1
        L73:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        L76:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        L79:
            r2.releaseIntercepted()
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.v0.a(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // kotlinx.coroutines.flow.InterfaceC5002j
    public final Object emit(Object obj, kotlin.coroutines.h hVar) {
        return this.a.emit(obj, hVar);
    }
}
