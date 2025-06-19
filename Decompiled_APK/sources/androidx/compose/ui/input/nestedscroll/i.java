package androidx.compose.ui.input.nestedscroll;

import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.q0;
import androidx.compose.ui.p;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class i extends p implements q0, a {
    public a n;
    public e o;
    public final String p;

    public i(a aVar, e eVar) {
        this.n = aVar;
        this.o = eVar == null ? new e() : eVar;
        this.p = "androidx.compose.ui.input.nestedscroll.NestedScrollNode";
    }

    @Override // androidx.compose.ui.p
    public final void E0() {
        e eVar = this.o;
        eVar.a = this;
        eVar.b = new b(this, 1);
        eVar.c = A0();
    }

    @Override // androidx.compose.ui.p
    public final void F0() {
        e eVar = this.o;
        if (eVar.a == this) {
            eVar.a = null;
        }
    }

    @Override // androidx.compose.ui.input.nestedscroll.a
    public final long L(int i, long j) {
        boolean z = this.m;
        i iVar = null;
        if (z && z) {
            iVar = (i) AbstractC0910f.k(this);
        }
        long jL = iVar != null ? iVar.L(i, j) : 0L;
        return androidx.compose.ui.geometry.b.h(jL, this.n.L(i, androidx.compose.ui.geometry.b.g(j, jL)));
    }

    public final C M0() {
        i iVar = this.m ? (i) AbstractC0910f.k(this) : null;
        if (iVar != null) {
            return iVar.M0();
        }
        C c = this.o.c;
        if (c != null) {
            return c;
        }
        throw new IllegalStateException("in order to access nested coroutine scope you need to attach dispatcher to the `Modifier.nestedScroll` first.");
    }

    /* JADX WARN: Code restructure failed: missing block: B:30:0x007c, code lost:
    
        if (r12 != r1) goto L32;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // androidx.compose.ui.input.nestedscroll.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object i0(long r10, kotlin.coroutines.h r12) {
        /*
            r9 = this;
            boolean r0 = r12 instanceof androidx.compose.ui.input.nestedscroll.h
            if (r0 == 0) goto L13
            r0 = r12
            androidx.compose.ui.input.nestedscroll.h r0 = (androidx.compose.ui.input.nestedscroll.h) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L1a
        L13:
            androidx.compose.ui.input.nestedscroll.h r0 = new androidx.compose.ui.input.nestedscroll.h
            kotlin.coroutines.jvm.internal.c r12 = (kotlin.coroutines.jvm.internal.c) r12
            r0.<init>(r9, r12)
        L1a:
            java.lang.Object r12 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 0
            r4 = 2
            r5 = 1
            if (r2 == 0) goto L3f
            if (r2 == r5) goto L37
            if (r2 != r4) goto L2f
            long r10 = r0.k
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto L7f
        L2f:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r11 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r11)
            throw r10
        L37:
            long r10 = r0.k
            androidx.compose.ui.input.nestedscroll.i r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto L60
        L3f:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            boolean r12 = r9.m
            if (r12 == 0) goto L4f
            if (r12 == 0) goto L4f
            androidx.compose.ui.node.q0 r12 = androidx.compose.ui.node.AbstractC0910f.k(r9)
            androidx.compose.ui.input.nestedscroll.i r12 = (androidx.compose.ui.input.nestedscroll.i) r12
            goto L50
        L4f:
            r12 = r3
        L50:
            if (r12 == 0) goto L68
            r0.j = r9
            r0.k = r10
            r0.n = r5
            java.lang.Object r12 = r12.i0(r10, r0)
            if (r12 != r1) goto L5f
            goto L7e
        L5f:
            r2 = r9
        L60:
            androidx.compose.ui.unit.o r12 = (androidx.compose.ui.unit.o) r12
            long r5 = r12.a
        L64:
            r7 = r5
            r5 = r10
            r10 = r7
            goto L6c
        L68:
            r5 = 0
            r2 = r9
            goto L64
        L6c:
            androidx.compose.ui.input.nestedscroll.a r12 = r2.n
            long r5 = androidx.compose.ui.unit.o.d(r5, r10)
            r0.j = r3
            r0.k = r10
            r0.n = r4
            java.lang.Object r12 = r12.i0(r5, r0)
            if (r12 != r1) goto L7f
        L7e:
            return r1
        L7f:
            androidx.compose.ui.unit.o r12 = (androidx.compose.ui.unit.o) r12
            long r0 = r12.a
            long r10 = androidx.compose.ui.unit.o.e(r10, r0)
            androidx.compose.ui.unit.o r12 = new androidx.compose.ui.unit.o
            r12.<init>(r10)
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.input.nestedscroll.i.i0(long, kotlin.coroutines.h):java.lang.Object");
    }

    @Override // androidx.compose.ui.node.q0
    public final Object m() {
        return this.p;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    @Override // androidx.compose.ui.input.nestedscroll.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object p(long r11, long r13, kotlin.coroutines.h r15) {
        /*
            r10 = this;
            boolean r0 = r15 instanceof androidx.compose.ui.input.nestedscroll.g
            if (r0 == 0) goto L14
            r0 = r15
            androidx.compose.ui.input.nestedscroll.g r0 = (androidx.compose.ui.input.nestedscroll.g) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L14
            int r1 = r1 - r2
            r0.o = r1
        L12:
            r6 = r0
            goto L1c
        L14:
            androidx.compose.ui.input.nestedscroll.g r0 = new androidx.compose.ui.input.nestedscroll.g
            kotlin.coroutines.jvm.internal.c r15 = (kotlin.coroutines.jvm.internal.c) r15
            r0.<init>(r10, r15)
            goto L12
        L1c:
            java.lang.Object r15 = r6.m
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.o
            r7 = 2
            r2 = 1
            if (r1 == 0) goto L42
            if (r1 == r2) goto L38
            if (r1 != r7) goto L30
            long r11 = r6.k
            androidx.glance.appwidget.protobuf.Z.e(r15)
            goto L88
        L30:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r12)
            throw r11
        L38:
            long r13 = r6.l
            long r11 = r6.k
            androidx.compose.ui.input.nestedscroll.i r1 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r15)
            goto L5b
        L42:
            androidx.glance.appwidget.protobuf.Z.e(r15)
            androidx.compose.ui.input.nestedscroll.a r1 = r10.n
            r6.j = r10
            r6.k = r11
            r6.l = r13
            r6.o = r2
            r2 = r11
            r4 = r13
            java.lang.Object r15 = r1.p(r2, r4, r6)
            if (r15 != r0) goto L58
            goto L86
        L58:
            r1 = r10
            r11 = r2
            r13 = r4
        L5b:
            androidx.compose.ui.unit.o r15 = (androidx.compose.ui.unit.o) r15
            long r8 = r15.a
            boolean r15 = r1.m
            r2 = 0
            if (r15 == 0) goto L6e
            if (r15 == 0) goto L6e
            androidx.compose.ui.node.q0 r15 = androidx.compose.ui.node.AbstractC0910f.k(r1)
            androidx.compose.ui.input.nestedscroll.i r15 = (androidx.compose.ui.input.nestedscroll.i) r15
            r1 = r15
            goto L6f
        L6e:
            r1 = r2
        L6f:
            if (r1 == 0) goto L8e
            long r11 = androidx.compose.ui.unit.o.e(r11, r8)
            long r4 = androidx.compose.ui.unit.o.d(r13, r8)
            r6.j = r2
            r6.k = r8
            r6.o = r7
            r2 = r11
            java.lang.Object r15 = r1.p(r2, r4, r6)
            if (r15 != r0) goto L87
        L86:
            return r0
        L87:
            r11 = r8
        L88:
            androidx.compose.ui.unit.o r15 = (androidx.compose.ui.unit.o) r15
            long r13 = r15.a
            r8 = r11
            goto L90
        L8e:
            r13 = 0
        L90:
            long r11 = androidx.compose.ui.unit.o.e(r8, r13)
            androidx.compose.ui.unit.o r13 = new androidx.compose.ui.unit.o
            r13.<init>(r11)
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.input.nestedscroll.i.p(long, long, kotlin.coroutines.h):java.lang.Object");
    }

    @Override // androidx.compose.ui.input.nestedscroll.a
    public final long s0(long j, long j2, int i) {
        long jS0 = this.n.s0(j, j2, i);
        boolean z = this.m;
        i iVar = null;
        if (z && z) {
            iVar = (i) AbstractC0910f.k(this);
        }
        i iVar2 = iVar;
        return androidx.compose.ui.geometry.b.h(jS0, iVar2 != null ? iVar2.s0(androidx.compose.ui.geometry.b.h(j, jS0), androidx.compose.ui.geometry.b.g(j2, jS0), i) : 0L);
    }
}
