package kotlinx.coroutines.flow;

import androidx.paging.C1315g;
import java.util.List;

/* loaded from: classes3.dex */
public final class x0 implements a0 {
    public final d0 a;
    public final C1315g b;

    public x0(d0 d0Var, C1315g c1315g) {
        this.a = d0Var;
        this.b = c1315g;
    }

    @Override // kotlinx.coroutines.flow.a0
    public final List a() {
        return this.a.a();
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // kotlinx.coroutines.flow.InterfaceC4992i
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(kotlinx.coroutines.flow.InterfaceC5002j r5, kotlin.coroutines.h r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof kotlinx.coroutines.flow.w0
            if (r0 == 0) goto L13
            r0 = r6
            kotlinx.coroutines.flow.w0 r0 = (kotlinx.coroutines.flow.w0) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            kotlinx.coroutines.flow.w0 r0 = new kotlinx.coroutines.flow.w0
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L34
            if (r2 == r3) goto L2b
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2b:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            kotlin.KotlinNothingValueException r5 = new kotlin.KotlinNothingValueException
            r5.<init>()
            throw r5
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            kotlinx.coroutines.flow.v0 r6 = new kotlinx.coroutines.flow.v0
            androidx.paging.g r2 = r4.b
            r6.<init>(r5, r2)
            r0.l = r3
            kotlinx.coroutines.flow.d0 r5 = r4.a
            r5.b(r6, r0)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.x0.b(kotlinx.coroutines.flow.j, kotlin.coroutines.h):java.lang.Object");
    }
}
