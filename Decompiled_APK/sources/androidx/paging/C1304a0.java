package androidx.paging;

import kotlinx.coroutines.flow.InterfaceC5002j;

/* renamed from: androidx.paging.a0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1304a0 implements InterfaceC5002j {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;

    public /* synthetic */ C1304a0(Object obj, int i, int i2) {
        this.a = i2;
        this.c = obj;
        this.b = i;
    }

    /* JADX WARN: Removed duplicated region for block: B:31:0x0071  */
    /* JADX WARN: Removed duplicated region for block: B:9:0x0018  */
    @Override // kotlinx.coroutines.flow.InterfaceC5002j
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object emit(java.lang.Object r6, kotlin.coroutines.h r7) {
        /*
            r5 = this;
            int r0 = r5.a
            switch(r0) {
                case 0: goto L5e;
                default: goto L5;
            }
        L5:
            boolean r0 = r7 instanceof kotlinx.coroutines.flow.internal.n
            if (r0 == 0) goto L18
            r0 = r7
            kotlinx.coroutines.flow.internal.n r0 = (kotlinx.coroutines.flow.internal.n) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L18
            int r1 = r1 - r2
            r0.l = r1
            goto L1d
        L18:
            kotlinx.coroutines.flow.internal.n r0 = new kotlinx.coroutines.flow.internal.n
            r0.<init>(r5, r7)
        L1d:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3b
            if (r2 == r4) goto L37
            if (r2 != r3) goto L2f
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L5b
        L2f:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L37:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L52
        L3b:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlin.collections.IndexedValue r7 = new kotlin.collections.IndexedValue
            int r2 = r5.b
            r7.<init>(r2, r6)
            r0.l = r4
            java.lang.Object r6 = r5.c
            kotlinx.coroutines.channels.h r6 = (kotlinx.coroutines.channels.h) r6
            java.lang.Object r6 = r6.s(r7, r0)
            if (r6 != r1) goto L52
            goto L5d
        L52:
            r0.l = r3
            java.lang.Object r6 = kotlinx.coroutines.E.M(r0)
            if (r6 != r1) goto L5b
            goto L5d
        L5b:
            kotlin.Unit r1 = kotlin.Unit.a
        L5d:
            return r1
        L5e:
            boolean r0 = r7 instanceof androidx.paging.Z
            if (r0 == 0) goto L71
            r0 = r7
            androidx.paging.Z r0 = (androidx.paging.Z) r0
            int r1 = r0.k
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L71
            int r1 = r1 - r2
            r0.k = r1
            goto L76
        L71:
            androidx.paging.Z r0 = new androidx.paging.Z
            r0.<init>(r5, r7)
        L76:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.k
            r3 = 1
            if (r2 == 0) goto L8d
            if (r2 != r3) goto L85
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto La6
        L85:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L8d:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            androidx.paging.k1 r6 = (androidx.paging.k1) r6
            androidx.paging.y r7 = new androidx.paging.y
            int r2 = r5.b
            r7.<init>(r2, r6)
            r0.k = r3
            java.lang.Object r6 = r5.c
            kotlinx.coroutines.flow.j r6 = (kotlinx.coroutines.flow.InterfaceC5002j) r6
            java.lang.Object r6 = r6.emit(r7, r0)
            if (r6 != r1) goto La6
            goto La8
        La6:
            kotlin.Unit r1 = kotlin.Unit.a
        La8:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.paging.C1304a0.emit(java.lang.Object, kotlin.coroutines.h):java.lang.Object");
    }
}
