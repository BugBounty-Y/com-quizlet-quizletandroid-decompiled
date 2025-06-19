package kotlinx.coroutines.flow;

/* loaded from: classes3.dex */
public final class C implements InterfaceC5002j {
    public final /* synthetic */ kotlin.jvm.internal.H a;
    public final /* synthetic */ int b;
    public final /* synthetic */ InterfaceC5002j c;

    public C(kotlin.jvm.internal.H h, int i, InterfaceC5002j interfaceC5002j) {
        this.a = h;
        this.b = i;
        this.c = interfaceC5002j;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // kotlinx.coroutines.flow.InterfaceC5002j
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object emit(java.lang.Object r6, kotlin.coroutines.h r7) {
        /*
            r5 = this;
            boolean r0 = r7 instanceof kotlinx.coroutines.flow.B
            if (r0 == 0) goto L13
            r0 = r7
            kotlinx.coroutines.flow.B r0 = (kotlinx.coroutines.flow.B) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            kotlinx.coroutines.flow.B r0 = new kotlinx.coroutines.flow.B
            r0.<init>(r5, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L45
        L27:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlin.jvm.internal.H r7 = r5.a
            int r2 = r7.a
            int r4 = r5.b
            if (r2 < r4) goto L48
            r0.l = r3
            kotlinx.coroutines.flow.j r7 = r5.c
            java.lang.Object r6 = r7.emit(r6, r0)
            if (r6 != r1) goto L45
            return r1
        L45:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        L48:
            int r2 = r2 + r3
            r7.a = r2
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.C.emit(java.lang.Object, kotlin.coroutines.h):java.lang.Object");
    }
}
