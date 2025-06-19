package androidx.compose.foundation.gestures;

/* renamed from: androidx.compose.foundation.gestures.g0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0326g0 implements androidx.compose.ui.unit.b {
    public final /* synthetic */ androidx.compose.ui.unit.b a;
    public boolean b;
    public boolean c;
    public final kotlinx.coroutines.sync.c d = new kotlinx.coroutines.sync.c(false);

    public C0326g0(androidx.compose.ui.unit.b bVar) {
        this.a = bVar;
    }

    @Override // androidx.compose.ui.unit.b
    public final long K(float f) {
        return this.a.K(f);
    }

    @Override // androidx.compose.ui.unit.b
    public final float O(int i) {
        return this.a.O(i);
    }

    @Override // androidx.compose.ui.unit.b
    public final float R(float f) {
        return this.a.R(f);
    }

    @Override // androidx.compose.ui.unit.b
    public final float Z() {
        return this.a.Z();
    }

    @Override // androidx.compose.ui.unit.b
    public final float a() {
        return this.a.a();
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof androidx.compose.foundation.gestures.C0322e0
            if (r0 == 0) goto L13
            r0 = r5
            androidx.compose.foundation.gestures.e0 r0 = (androidx.compose.foundation.gestures.C0322e0) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            androidx.compose.foundation.gestures.e0 r0 = new androidx.compose.foundation.gestures.e0
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.compose.foundation.gestures.g0 r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L42
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r0.j = r4
            r0.m = r3
            kotlinx.coroutines.sync.c r5 = r4.d
            java.lang.Object r5 = r5.d(r0)
            if (r5 != r1) goto L41
            return r1
        L41:
            r0 = r4
        L42:
            r5 = 0
            r0.b = r5
            r0.c = r5
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.C0326g0.b(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object c(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof androidx.compose.foundation.gestures.C0324f0
            if (r0 == 0) goto L13
            r0 = r5
            androidx.compose.foundation.gestures.f0 r0 = (androidx.compose.foundation.gestures.C0324f0) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            androidx.compose.foundation.gestures.f0 r0 = new androidx.compose.foundation.gestures.f0
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.compose.foundation.gestures.g0 r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L4a
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            boolean r5 = r4.b
            if (r5 != 0) goto L51
            boolean r5 = r4.c
            if (r5 != 0) goto L51
            r0.j = r4
            r0.m = r3
            kotlinx.coroutines.sync.c r5 = r4.d
            java.lang.Object r5 = r5.d(r0)
            if (r5 != r1) goto L49
            return r1
        L49:
            r0 = r4
        L4a:
            kotlinx.coroutines.sync.c r5 = r0.d
            r1 = 0
            r5.f(r1)
            goto L52
        L51:
            r0 = r4
        L52:
            boolean r5 = r0.b
            java.lang.Boolean r5 = java.lang.Boolean.valueOf(r5)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.C0326g0.c(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // androidx.compose.ui.unit.b
    public final float c0(float f) {
        return this.a.c0(f);
    }

    @Override // androidx.compose.ui.unit.b
    public final int j0(long j) {
        return this.a.j0(j);
    }

    @Override // androidx.compose.ui.unit.b
    public final int m0(float f) {
        return this.a.m0(f);
    }

    @Override // androidx.compose.ui.unit.b
    public final long q0(long j) {
        return this.a.q0(j);
    }

    @Override // androidx.compose.ui.unit.b
    public final long r(float f) {
        return this.a.r(f);
    }

    @Override // androidx.compose.ui.unit.b
    public final long s(long j) {
        return this.a.s(j);
    }

    @Override // androidx.compose.ui.unit.b
    public final float v0(long j) {
        return this.a.v0(j);
    }

    @Override // androidx.compose.ui.unit.b
    public final float y(long j) {
        return this.a.y(j);
    }
}
