package androidx.compose.ui.input.pointer;

/* loaded from: classes.dex */
public final class y extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ z k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public y(z zVar, kotlin.coroutines.jvm.internal.a aVar) {
        super(aVar);
        this.k = zVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0022  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r9) {
        /*
            r8 = this;
            r8.j = r9
            int r9 = r8.l
            r0 = -2147483648(0xffffffff80000000, float:-0.0)
            r9 = r9 | r0
            r8.l = r9
            r9 = 0
            androidx.compose.ui.input.pointer.z r0 = r8.k
            r1 = 0
            r0.getClass()
            boolean r3 = r8 instanceof androidx.compose.ui.input.pointer.y
            if (r3 == 0) goto L22
            int r3 = r8.l
            r4 = -2147483648(0xffffffff80000000, float:-0.0)
            r5 = r3 & r4
            if (r5 == 0) goto L22
            int r3 = r3 - r4
            r8.l = r3
            r3 = r8
            goto L27
        L22:
            androidx.compose.ui.input.pointer.y r3 = new androidx.compose.ui.input.pointer.y
            r3.<init>(r0, r8)
        L27:
            java.lang.Object r4 = r3.j
            kotlin.coroutines.intrinsics.a r5 = kotlin.coroutines.intrinsics.a.a
            int r6 = r3.l
            r7 = 1
            if (r6 == 0) goto L3e
            if (r6 != r7) goto L36
            androidx.glance.appwidget.protobuf.Z.e(r4)     // Catch: androidx.compose.ui.input.pointer.PointerEventTimeoutCancellationException -> L4b
            goto L4c
        L36:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L3e:
            androidx.glance.appwidget.protobuf.Z.e(r4)
            r3.l = r7     // Catch: androidx.compose.ui.input.pointer.PointerEventTimeoutCancellationException -> L4b
            java.lang.Object r4 = r0.f(r1, r9, r3)     // Catch: androidx.compose.ui.input.pointer.PointerEventTimeoutCancellationException -> L4b
            if (r4 != r5) goto L4c
            r4 = r5
            goto L4c
        L4b:
            r4 = 0
        L4c:
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.input.pointer.y.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
