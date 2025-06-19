package androidx.paging;

import kotlinx.coroutines.flow.InterfaceC5002j;

/* renamed from: androidx.paging.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1307c implements InterfaceC5002j {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ InterfaceC5002j b;
    public final /* synthetic */ kotlin.jvm.internal.H c;

    public C1307c(kotlin.jvm.internal.H h, InterfaceC5002j interfaceC5002j) {
        this.c = h;
        this.b = interfaceC5002j;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object a(kotlin.collections.IndexedValue r5, kotlin.coroutines.h r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof androidx.paging.C1305b
            if (r0 == 0) goto L13
            r0 = r6
            androidx.paging.b r0 = (androidx.paging.C1305b) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            androidx.paging.b r0 = new androidx.paging.b
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            kotlin.collections.IndexedValue r5 = r0.k
            androidx.paging.c r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L53
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            kotlin.jvm.internal.Intrinsics.d(r5)
            kotlin.jvm.internal.H r6 = r4.c
            int r6 = r6.a
            int r2 = r5.a
            if (r2 <= r6) goto L59
            r0.j = r4
            r0.k = r5
            r0.n = r3
            kotlinx.coroutines.flow.j r6 = r4.b
            java.lang.Object r2 = r5.b
            java.lang.Object r6 = r6.emit(r2, r0)
            if (r6 != r1) goto L52
            return r1
        L52:
            r0 = r4
        L53:
            kotlin.jvm.internal.H r6 = r0.c
            int r5 = r5.a
            r6.a = r5
        L59:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.paging.C1307c.a(kotlin.collections.IndexedValue, kotlin.coroutines.h):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:9:0x0018  */
    @Override // kotlinx.coroutines.flow.InterfaceC5002j
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object emit(java.lang.Object r7, kotlin.coroutines.h r8) {
        /*
            r6 = this;
            int r0 = r6.a
            switch(r0) {
                case 0: goto L5c;
                default: goto L5;
            }
        L5:
            boolean r0 = r8 instanceof kotlinx.coroutines.flow.U
            if (r0 == 0) goto L18
            r0 = r8
            kotlinx.coroutines.flow.U r0 = (kotlinx.coroutines.flow.U) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L18
            int r1 = r1 - r2
            r0.l = r1
            goto L1d
        L18:
            kotlinx.coroutines.flow.U r0 = new kotlinx.coroutines.flow.U
            r0.<init>(r6, r8)
        L1d:
            java.lang.Object r8 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L34
            if (r2 != r3) goto L2c
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L51
        L2c:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            kotlin.collections.IndexedValue r8 = new kotlin.collections.IndexedValue
            kotlin.jvm.internal.H r2 = r6.c
            int r4 = r2.a
            int r5 = r4 + 1
            r2.a = r5
            if (r4 < 0) goto L54
            r8.<init>(r4, r7)
            r0.l = r3
            kotlinx.coroutines.flow.j r7 = r6.b
            java.lang.Object r7 = r7.emit(r8, r0)
            if (r7 != r1) goto L51
            goto L53
        L51:
            kotlin.Unit r1 = kotlin.Unit.a
        L53:
            return r1
        L54:
            java.lang.ArithmeticException r7 = new java.lang.ArithmeticException
            java.lang.String r8 = "Index overflow has happened"
            r7.<init>(r8)
            throw r7
        L5c:
            kotlin.collections.IndexedValue r7 = (kotlin.collections.IndexedValue) r7
            java.lang.Object r7 = r6.a(r7, r8)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.paging.C1307c.emit(java.lang.Object, kotlin.coroutines.h):java.lang.Object");
    }

    public C1307c(InterfaceC5002j interfaceC5002j, kotlin.jvm.internal.H h) {
        this.b = interfaceC5002j;
        this.c = h;
    }
}
