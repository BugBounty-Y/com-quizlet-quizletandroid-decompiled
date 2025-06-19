package kotlinx.coroutines.flow;

/* renamed from: kotlinx.coroutines.flow.v, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5013v implements InterfaceC4992i {
    public final /* synthetic */ InterfaceC4992i a;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i b;

    /* JADX WARN: Multi-variable type inference failed */
    public C5013v(InterfaceC4992i interfaceC4992i, kotlin.jvm.functions.c cVar) {
        this.a = interfaceC4992i;
        this.b = (kotlin.coroutines.jvm.internal.i) cVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:35:0x007b  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x009f A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:56:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r2v4, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.c] */
    /* JADX WARN: Type inference failed for: r9v6, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.c] */
    @Override // kotlinx.coroutines.flow.InterfaceC4992i
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(kotlinx.coroutines.flow.InterfaceC5002j r9, kotlin.coroutines.h r10) throws java.lang.Throwable {
        /*
            r8 = this;
            boolean r0 = r10 instanceof kotlinx.coroutines.flow.C5012u
            if (r0 == 0) goto L13
            r0 = r10
            kotlinx.coroutines.flow.u r0 = (kotlinx.coroutines.flow.C5012u) r0
            int r1 = r0.k
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.k = r1
            goto L18
        L13:
            kotlinx.coroutines.flow.u r0 = new kotlinx.coroutines.flow.u
            r0.<init>(r8, r10)
        L18:
            java.lang.Object r10 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.k
            r3 = 3
            r4 = 2
            r5 = 1
            r6 = 0
            if (r2 == 0) goto L50
            if (r2 == r5) goto L44
            if (r2 == r4) goto L3c
            if (r2 != r3) goto L34
            java.lang.Object r9 = r0.m
            kotlinx.coroutines.flow.internal.C r9 = (kotlinx.coroutines.flow.internal.C) r9
            androidx.glance.appwidget.protobuf.Z.e(r10)     // Catch: java.lang.Throwable -> L32
            goto L7c
        L32:
            r10 = move-exception
            goto L86
        L34:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L3c:
            java.lang.Object r9 = r0.m
            java.lang.Throwable r9 = (java.lang.Throwable) r9
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto La0
        L44:
            kotlinx.coroutines.flow.j r9 = r0.n
            java.lang.Object r2 = r0.m
            kotlinx.coroutines.flow.v r2 = (kotlinx.coroutines.flow.C5013v) r2
            androidx.glance.appwidget.protobuf.Z.e(r10)     // Catch: java.lang.Throwable -> L4e
            goto L63
        L4e:
            r9 = move-exception
            goto L8c
        L50:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            kotlinx.coroutines.flow.i r10 = r8.a     // Catch: java.lang.Throwable -> L8a
            r0.m = r8     // Catch: java.lang.Throwable -> L8a
            r0.n = r9     // Catch: java.lang.Throwable -> L8a
            r0.k = r5     // Catch: java.lang.Throwable -> L8a
            java.lang.Object r10 = r10.b(r9, r0)     // Catch: java.lang.Throwable -> L8a
            if (r10 != r1) goto L62
            goto L9f
        L62:
            r2 = r8
        L63:
            kotlinx.coroutines.flow.internal.C r10 = new kotlinx.coroutines.flow.internal.C
            kotlin.coroutines.CoroutineContext r4 = r0.getContext()
            r10.<init>(r9, r4)
            kotlin.coroutines.jvm.internal.i r9 = r2.b     // Catch: java.lang.Throwable -> L82
            r0.m = r10     // Catch: java.lang.Throwable -> L82
            r0.n = r6     // Catch: java.lang.Throwable -> L82
            r0.k = r3     // Catch: java.lang.Throwable -> L82
            java.lang.Object r9 = r9.invoke(r10, r6, r0)     // Catch: java.lang.Throwable -> L82
            if (r9 != r1) goto L7b
            goto L9f
        L7b:
            r9 = r10
        L7c:
            r9.releaseIntercepted()
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        L82:
            r9 = move-exception
            r7 = r10
            r10 = r9
            r9 = r7
        L86:
            r9.releaseIntercepted()
            throw r10
        L8a:
            r9 = move-exception
            r2 = r8
        L8c:
            kotlinx.coroutines.flow.y0 r10 = new kotlinx.coroutines.flow.y0
            r10.<init>(r9)
            kotlin.coroutines.jvm.internal.i r2 = r2.b
            r0.m = r9
            r0.n = r6
            r0.k = r4
            java.lang.Object r10 = kotlinx.coroutines.flow.e0.d(r10, r2, r9, r0)
            if (r10 != r1) goto La0
        L9f:
            return r1
        La0:
            throw r9
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.C5013v.b(kotlinx.coroutines.flow.j, kotlin.coroutines.h):java.lang.Object");
    }
}
