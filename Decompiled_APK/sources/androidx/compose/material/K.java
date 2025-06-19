package androidx.compose.material;

import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class K implements androidx.compose.ui.input.nestedscroll.a {
    public final /* synthetic */ C0575s a;

    public K(C0575s c0575s) {
        this.a = c0575s;
    }

    @Override // androidx.compose.ui.input.nestedscroll.a
    public final long L(int i, long j) {
        float fE = androidx.compose.ui.geometry.b.e(j);
        if (fE >= DefinitionKt.NO_Float_VALUE || i != 1) {
            return 0L;
        }
        C0575s c0575s = this.a;
        float f = c0575s.f(fE);
        float fE2 = Float.isNaN(c0575s.e()) ? 0.0f : c0575s.e();
        c0575s.i.j(f);
        return Q4.c(DefinitionKt.NO_Float_VALUE, f - fE2);
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x006d  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r5v3, types: [java.lang.Object, java.util.Map] */
    @Override // androidx.compose.ui.input.nestedscroll.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object i0(long r7, kotlin.coroutines.h r9) {
        /*
            r6 = this;
            boolean r0 = r9 instanceof androidx.compose.material.J
            if (r0 == 0) goto L13
            r0 = r9
            androidx.compose.material.J r0 = (androidx.compose.material.J) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L1a
        L13:
            androidx.compose.material.J r0 = new androidx.compose.material.J
            kotlin.coroutines.jvm.internal.c r9 = (kotlin.coroutines.jvm.internal.c) r9
            r0.<init>(r6, r9)
        L1a:
            java.lang.Object r9 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            long r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L6f
        L2b:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            float r9 = androidx.compose.ui.unit.o.c(r7)
            androidx.compose.material.s r2 = r6.a
            float r4 = r2.g()
            r5 = 0
            int r5 = (r9 > r5 ? 1 : (r9 == r5 ? 0 : -1))
            if (r5 >= 0) goto L6d
            androidx.compose.material.G r5 = r2.d()
            java.lang.Object r5 = r5.a
            java.util.Collection r5 = r5.values()
            java.lang.Iterable r5 = (java.lang.Iterable) r5
            java.lang.Float r5 = kotlin.collections.CollectionsKt.Z(r5)
            if (r5 == 0) goto L5c
            float r5 = r5.floatValue()
            goto L5e
        L5c:
            r5 = 2143289344(0x7fc00000, float:NaN)
        L5e:
            int r4 = (r4 > r5 ? 1 : (r4 == r5 ? 0 : -1))
            if (r4 <= 0) goto L6d
            r0.j = r7
            r0.m = r3
            java.lang.Object r9 = r2.j(r9, r0)
            if (r9 != r1) goto L6f
            return r1
        L6d:
            r7 = 0
        L6f:
            androidx.compose.ui.unit.o r9 = new androidx.compose.ui.unit.o
            r9.<init>(r7)
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material.K.i0(long, kotlin.coroutines.h):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // androidx.compose.ui.input.nestedscroll.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object p(long r3, long r5, kotlin.coroutines.h r7) {
        /*
            r2 = this;
            boolean r3 = r7 instanceof androidx.compose.material.I
            if (r3 == 0) goto L13
            r3 = r7
            androidx.compose.material.I r3 = (androidx.compose.material.I) r3
            int r4 = r3.m
            r0 = -2147483648(0xffffffff80000000, float:-0.0)
            r1 = r4 & r0
            if (r1 == 0) goto L13
            int r4 = r4 - r0
            r3.m = r4
            goto L1a
        L13:
            androidx.compose.material.I r3 = new androidx.compose.material.I
            kotlin.coroutines.jvm.internal.c r7 = (kotlin.coroutines.jvm.internal.c) r7
            r3.<init>(r2, r7)
        L1a:
            java.lang.Object r4 = r3.k
            kotlin.coroutines.intrinsics.a r7 = kotlin.coroutines.intrinsics.a.a
            int r0 = r3.m
            r1 = 1
            if (r0 == 0) goto L33
            if (r0 != r1) goto L2b
            long r5 = r3.j
            androidx.glance.appwidget.protobuf.Z.e(r4)
            goto L47
        L2b:
            java.lang.IllegalStateException r3 = new java.lang.IllegalStateException
            java.lang.String r4 = "call to 'resume' before 'invoke' with coroutine"
            r3.<init>(r4)
            throw r3
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r4)
            float r4 = androidx.compose.ui.unit.o.c(r5)
            r3.j = r5
            r3.m = r1
            androidx.compose.material.s r0 = r2.a
            java.lang.Object r3 = r0.j(r4, r3)
            if (r3 != r7) goto L47
            return r7
        L47:
            androidx.compose.ui.unit.o r3 = new androidx.compose.ui.unit.o
            r3.<init>(r5)
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material.K.p(long, long, kotlin.coroutines.h):java.lang.Object");
    }

    @Override // androidx.compose.ui.input.nestedscroll.a
    public final long s0(long j, long j2, int i) {
        if (i != 1) {
            return 0L;
        }
        float fE = androidx.compose.ui.geometry.b.e(j2);
        C0575s c0575s = this.a;
        float f = c0575s.f(fE);
        float fE2 = Float.isNaN(c0575s.e()) ? 0.0f : c0575s.e();
        c0575s.i.j(f);
        return Q4.c(DefinitionKt.NO_Float_VALUE, f - fE2);
    }
}
