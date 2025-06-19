package kotlinx.coroutines.flow;

/* renamed from: kotlinx.coroutines.flow.q, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5009q implements InterfaceC5002j {
    public final /* synthetic */ int a;
    public final /* synthetic */ kotlinx.coroutines.channels.u b;

    public /* synthetic */ C5009q(kotlinx.coroutines.channels.u uVar, int i) {
        this.a = i;
        this.b = uVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x0063  */
    /* JADX WARN: Removed duplicated region for block: B:9:0x0018  */
    @Override // kotlinx.coroutines.flow.InterfaceC5002j
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object emit(java.lang.Object r5, kotlin.coroutines.h r6) {
        /*
            r4 = this;
            int r0 = r4.a
            switch(r0) {
                case 0: goto L50;
                default: goto L5;
            }
        L5:
            boolean r0 = r6 instanceof kotlinx.coroutines.flow.internal.u
            if (r0 == 0) goto L18
            r0 = r6
            kotlinx.coroutines.flow.internal.u r0 = (kotlinx.coroutines.flow.internal.u) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L18
            int r1 = r1 - r2
            r0.l = r1
            goto L1d
        L18:
            kotlinx.coroutines.flow.internal.u r0 = new kotlinx.coroutines.flow.internal.u
            r0.<init>(r4, r6)
        L1d:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L34
            if (r2 != r3) goto L2c
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L4d
        L2c:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            kotlinx.coroutines.channels.u r6 = r4.b
            kotlinx.coroutines.channels.t r6 = (kotlinx.coroutines.channels.t) r6
            r6.getClass()
            if (r5 != 0) goto L42
            com.android.billingclient.api.a r5 = kotlinx.coroutines.flow.internal.AbstractC4994b.b
        L42:
            r0.l = r3
            kotlinx.coroutines.channels.h r6 = r6.d
            java.lang.Object r5 = r6.s(r5, r0)
            if (r5 != r1) goto L4d
            goto L4f
        L4d:
            kotlin.Unit r1 = kotlin.Unit.a
        L4f:
            return r1
        L50:
            boolean r0 = r6 instanceof kotlinx.coroutines.flow.C5008p
            if (r0 == 0) goto L63
            r0 = r6
            kotlinx.coroutines.flow.p r0 = (kotlinx.coroutines.flow.C5008p) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L63
            int r1 = r1 - r2
            r0.l = r1
            goto L68
        L63:
            kotlinx.coroutines.flow.p r0 = new kotlinx.coroutines.flow.p
            r0.<init>(r4, r6)
        L68:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L7f
            if (r2 != r3) goto L77
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L95
        L77:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L7f:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            if (r5 != 0) goto L86
            com.android.billingclient.api.a r5 = kotlinx.coroutines.flow.internal.AbstractC4994b.b
        L86:
            r0.l = r3
            kotlinx.coroutines.channels.u r6 = r4.b
            kotlinx.coroutines.channels.t r6 = (kotlinx.coroutines.channels.t) r6
            kotlinx.coroutines.channels.h r6 = r6.d
            java.lang.Object r5 = r6.s(r5, r0)
            if (r5 != r1) goto L95
            goto L97
        L95:
            kotlin.Unit r1 = kotlin.Unit.a
        L97:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.C5009q.emit(java.lang.Object, kotlin.coroutines.h):java.lang.Object");
    }
}
