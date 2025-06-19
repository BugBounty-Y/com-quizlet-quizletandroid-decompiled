package androidx.lifecycle;

/* renamed from: androidx.lifecycle.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1249j extends X {
    public androidx.camera.camera2.internal.c0 n;

    @Override // androidx.lifecycle.X, androidx.lifecycle.T
    public final void h() {
        super.h();
        androidx.camera.camera2.internal.c0 c0Var = this.n;
        if (c0Var != null) {
            kotlinx.coroutines.y0 y0Var = (kotlinx.coroutines.y0) c0Var.g;
            if (y0Var != null) {
                y0Var.j(null);
            }
            c0Var.g = null;
            if (((kotlinx.coroutines.y0) c0Var.f) != null) {
                return;
            }
            c0Var.f = kotlinx.coroutines.E.A((kotlinx.coroutines.internal.d) c0Var.d, null, null, new C1241c(c0Var, null), 3);
        }
    }

    @Override // androidx.lifecycle.X, androidx.lifecycle.T
    public final void i() {
        super.i();
        androidx.camera.camera2.internal.c0 c0Var = this.n;
        if (c0Var != null) {
            if (((kotlinx.coroutines.y0) c0Var.g) != null) {
                throw new IllegalStateException("Cancel call cannot happen without a maybeRun");
            }
            kotlinx.coroutines.scheduling.e eVar = kotlinx.coroutines.O.a;
            c0Var.g = kotlinx.coroutines.E.A((kotlinx.coroutines.internal.d) c0Var.d, kotlinx.coroutines.internal.m.a.e, null, new C1239b(c0Var, null), 2);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final kotlin.Unit n(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof androidx.lifecycle.C1248i
            if (r0 == 0) goto L13
            r0 = r5
            androidx.lifecycle.i r0 = (androidx.lifecycle.C1248i) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            androidx.lifecycle.i r0 = new androidx.lifecycle.i
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r0 = r0.l
            if (r0 == 0) goto L23
            r1 = 1
            if (r0 != r1) goto L27
        L23:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L2f
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L2f:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.lifecycle.C1249j.n(kotlin.coroutines.jvm.internal.c):kotlin.Unit");
    }
}
