package androidx.compose.ui.input.pointer;

import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.platform.Y0;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;

/* loaded from: classes.dex */
public final class z implements androidx.compose.ui.unit.b, kotlin.coroutines.h {
    public final C5028l a;
    public final /* synthetic */ B b;
    public C5028l c;
    public g d = g.b;
    public final kotlin.coroutines.n e = kotlin.coroutines.n.a;
    public final /* synthetic */ B f;

    public z(B b, C5028l c5028l) {
        this.f = b;
        this.a = c5028l;
        this.b = b;
    }

    @Override // androidx.compose.ui.unit.b
    public final long K(float f) {
        return this.b.K(f);
    }

    @Override // androidx.compose.ui.unit.b
    public final float O(int i) {
        return this.b.O(i);
    }

    @Override // androidx.compose.ui.unit.b
    public final float R(float f) {
        return f / this.b.a();
    }

    @Override // androidx.compose.ui.unit.b
    public final float Z() {
        return this.b.Z();
    }

    @Override // androidx.compose.ui.unit.b
    public final float a() {
        return this.b.a();
    }

    public final Object c(g gVar, kotlin.coroutines.jvm.internal.a frame) {
        C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(frame));
        c5028l.r();
        this.d = gVar;
        this.c = c5028l;
        Object objQ = c5028l.q();
        if (objQ == kotlin.coroutines.intrinsics.a.a) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return objQ;
    }

    @Override // androidx.compose.ui.unit.b
    public final float c0(float f) {
        return this.b.a() * f;
    }

    public final long d() {
        B b = this.f;
        b.getClass();
        long jQ0 = b.q0(AbstractC0910f.v(b).t.d());
        long j = b.v;
        return T4.a(Math.max(DefinitionKt.NO_Float_VALUE, androidx.compose.ui.geometry.e.d(jQ0) - ((int) (j >> 32))) / 2.0f, Math.max(DefinitionKt.NO_Float_VALUE, androidx.compose.ui.geometry.e.b(jQ0) - ((int) (j & 4294967295L))) / 2.0f);
    }

    public final Y0 e() {
        B b = this.f;
        b.getClass();
        return AbstractC0910f.v(b).t;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r7v0, types: [long] */
    /* JADX WARN: Type inference failed for: r7v1, types: [kotlinx.coroutines.j0] */
    /* JADX WARN: Type inference failed for: r7v4, types: [kotlinx.coroutines.j0] */
    /* JADX WARN: Type inference failed for: r7v7 */
    /* JADX WARN: Type inference failed for: r7v8 */
    /* JADX WARN: Type inference failed for: r9v0, types: [kotlin.jvm.functions.Function2] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object f(long r7, kotlin.jvm.functions.Function2 r9, kotlin.coroutines.jvm.internal.a r10) {
        /*
            r6 = this;
            boolean r0 = r10 instanceof androidx.compose.ui.input.pointer.w
            if (r0 == 0) goto L13
            r0 = r10
            androidx.compose.ui.input.pointer.w r0 = (androidx.compose.ui.input.pointer.w) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            androidx.compose.ui.input.pointer.w r0 = new androidx.compose.ui.input.pointer.w
            r0.<init>(r6, r10)
        L18:
            java.lang.Object r10 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            kotlinx.coroutines.y0 r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)     // Catch: java.lang.Throwable -> L29
            goto L6a
        L29:
            r8 = move-exception
            goto L70
        L2b:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            r4 = 0
            int r10 = (r7 > r4 ? 1 : (r7 == r4 ? 0 : -1))
            if (r10 > 0) goto L4e
            kotlinx.coroutines.l r10 = r6.c
            if (r10 == 0) goto L4e
            kotlin.p r2 = kotlin.r.b
            androidx.compose.ui.input.pointer.PointerEventTimeoutCancellationException r2 = new androidx.compose.ui.input.pointer.PointerEventTimeoutCancellationException
            r2.<init>(r7)
            kotlin.q r2 = androidx.glance.appwidget.protobuf.Z.b(r2)
            r10.resumeWith(r2)
        L4e:
            androidx.compose.ui.input.pointer.B r10 = r6.f
            kotlinx.coroutines.C r10 = r10.A0()
            androidx.compose.ui.input.pointer.x r2 = new androidx.compose.ui.input.pointer.x
            r4 = 0
            r2.<init>(r7, r6, r4)
            r7 = 3
            kotlinx.coroutines.y0 r7 = kotlinx.coroutines.E.A(r10, r4, r4, r2, r7)
            r0.j = r7     // Catch: java.lang.Throwable -> L29
            r0.m = r3     // Catch: java.lang.Throwable -> L29
            java.lang.Object r10 = r9.invoke(r6, r0)     // Catch: java.lang.Throwable -> L29
            if (r10 != r1) goto L6a
            return r1
        L6a:
            androidx.compose.ui.input.pointer.CancelTimeoutCancellationException r8 = androidx.compose.ui.input.pointer.CancelTimeoutCancellationException.a
            r7.j(r8)
            return r10
        L70:
            androidx.compose.ui.input.pointer.CancelTimeoutCancellationException r9 = androidx.compose.ui.input.pointer.CancelTimeoutCancellationException.a
            r7.j(r9)
            throw r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.input.pointer.z.f(long, kotlin.jvm.functions.Function2, kotlin.coroutines.jvm.internal.a):java.lang.Object");
    }

    @Override // kotlin.coroutines.h
    public final CoroutineContext getContext() {
        return this.e;
    }

    @Override // androidx.compose.ui.unit.b
    public final int j0(long j) {
        return this.b.j0(j);
    }

    @Override // androidx.compose.ui.unit.b
    public final int m0(float f) {
        return this.b.m0(f);
    }

    @Override // androidx.compose.ui.unit.b
    public final long q0(long j) {
        return this.b.q0(j);
    }

    @Override // androidx.compose.ui.unit.b
    public final long r(float f) {
        return this.b.r(f);
    }

    @Override // kotlin.coroutines.h
    public final void resumeWith(Object obj) {
        B b = this.f;
        synchronized (b.s) {
            b.s.n(this);
            Unit unit = Unit.a;
        }
        this.a.resumeWith(obj);
    }

    @Override // androidx.compose.ui.unit.b
    public final long s(long j) {
        return this.b.s(j);
    }

    @Override // androidx.compose.ui.unit.b
    public final float v0(long j) {
        return this.b.v0(j);
    }

    @Override // androidx.compose.ui.unit.b
    public final float y(long j) {
        return this.b.y(j);
    }
}
