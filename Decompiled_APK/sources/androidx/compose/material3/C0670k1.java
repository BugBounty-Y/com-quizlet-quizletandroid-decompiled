package androidx.compose.material3;

import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: androidx.compose.material3.k1, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0670k1 implements androidx.compose.ui.input.nestedscroll.a {
    public final /* synthetic */ com.quizlet.data.repository.achievements.h a;

    public C0670k1(com.quizlet.data.repository.achievements.h hVar) {
        this.a = hVar;
    }

    @Override // androidx.compose.ui.input.nestedscroll.a
    public final long L(int i, long j) {
        com.quizlet.data.repository.achievements.h hVar = this.a;
        hVar.getClass();
        if (!Boolean.TRUE.booleanValue() || androidx.compose.ui.geometry.b.e(j) > DefinitionKt.NO_Float_VALUE) {
            return 0L;
        }
        X4 x4 = (X4) hVar.a;
        float fB = x4.b();
        x4.d(androidx.compose.ui.geometry.b.e(j) + x4.b());
        if (fB == x4.b()) {
            return 0L;
        }
        return androidx.compose.ui.geometry.b.a(DefinitionKt.NO_Float_VALUE, 2, j);
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    @Override // androidx.compose.ui.input.nestedscroll.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object p(long r9, long r11, kotlin.coroutines.h r13) {
        /*
            r8 = this;
            boolean r0 = r13 instanceof androidx.compose.material3.C0664j1
            if (r0 == 0) goto L14
            r0 = r13
            androidx.compose.material3.j1 r0 = (androidx.compose.material3.C0664j1) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L14
            int r1 = r1 - r2
            r0.n = r1
        L12:
            r6 = r0
            goto L1c
        L14:
            androidx.compose.material3.j1 r0 = new androidx.compose.material3.j1
            kotlin.coroutines.jvm.internal.c r13 = (kotlin.coroutines.jvm.internal.c) r13
            r0.<init>(r8, r13)
            goto L12
        L1c:
            java.lang.Object r13 = r6.l
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.n
            r7 = 2
            r2 = 1
            if (r1 == 0) goto L40
            if (r1 == r2) goto L38
            if (r1 != r7) goto L30
            long r9 = r6.k
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L7c
        L30:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L38:
            long r11 = r6.k
            androidx.compose.material3.k1 r9 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L55
        L40:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            r6.j = r8
            r6.k = r11
            r6.n = r2
            r1 = r8
            r2 = r9
            r4 = r11
            java.lang.Object r13 = super.p(r2, r4, r6)
            if (r13 != r0) goto L53
            goto L7a
        L53:
            r9 = r8
            r11 = r4
        L55:
            androidx.compose.ui.unit.o r13 = (androidx.compose.ui.unit.o) r13
            long r1 = r13.a
            com.quizlet.data.repository.achievements.h r10 = r9.a
            java.lang.Object r10 = r10.a
            androidx.compose.material3.X4 r10 = (androidx.compose.material3.X4) r10
            float r11 = androidx.compose.ui.unit.o.c(r11)
            com.quizlet.data.repository.achievements.h r9 = r9.a
            java.lang.Object r12 = r9.c
            androidx.compose.animation.core.z r12 = (androidx.compose.animation.core.C0276z) r12
            r13 = 0
            r6.j = r13
            r6.k = r1
            r6.n = r7
            java.lang.Object r9 = r9.b
            androidx.compose.animation.core.n r9 = (androidx.compose.animation.core.InterfaceC0256n) r9
            java.lang.Object r13 = androidx.compose.material3.D.h(r10, r11, r12, r9, r6)
            if (r13 != r0) goto L7b
        L7a:
            return r0
        L7b:
            r9 = r1
        L7c:
            androidx.compose.ui.unit.o r13 = (androidx.compose.ui.unit.o) r13
            long r11 = r13.a
            long r9 = androidx.compose.ui.unit.o.e(r9, r11)
            androidx.compose.ui.unit.o r11 = new androidx.compose.ui.unit.o
            r11.<init>(r9)
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.C0670k1.p(long, long, kotlin.coroutines.h):java.lang.Object");
    }

    @Override // androidx.compose.ui.input.nestedscroll.a
    public final long s0(long j, long j2, int i) {
        com.quizlet.data.repository.achievements.h hVar = this.a;
        hVar.getClass();
        if (!Boolean.TRUE.booleanValue()) {
            return 0L;
        }
        X4 x4 = (X4) hVar.a;
        x4.b.j(androidx.compose.ui.geometry.b.e(j) + x4.b.i());
        if (androidx.compose.ui.geometry.b.e(j2) < DefinitionKt.NO_Float_VALUE || androidx.compose.ui.geometry.b.e(j) < DefinitionKt.NO_Float_VALUE) {
            float fB = x4.b();
            x4.d(androidx.compose.ui.geometry.b.e(j) + x4.b());
            return com.google.android.gms.internal.mlkit_vision_barcode.Q4.c(DefinitionKt.NO_Float_VALUE, x4.b() - fB);
        }
        if (androidx.compose.ui.geometry.b.e(j) == DefinitionKt.NO_Float_VALUE && androidx.compose.ui.geometry.b.e(j2) > DefinitionKt.NO_Float_VALUE) {
            x4.b.j(DefinitionKt.NO_Float_VALUE);
        }
        if (androidx.compose.ui.geometry.b.e(j2) <= DefinitionKt.NO_Float_VALUE) {
            return 0L;
        }
        float fB2 = x4.b();
        x4.d(androidx.compose.ui.geometry.b.e(j2) + x4.b());
        return com.google.android.gms.internal.mlkit_vision_barcode.Q4.c(DefinitionKt.NO_Float_VALUE, x4.b() - fB2);
    }
}
