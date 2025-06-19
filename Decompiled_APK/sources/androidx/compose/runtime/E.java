package androidx.compose.runtime;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class E extends androidx.compose.runtime.snapshots.A implements W0 {
    public final Function0 b;
    public final M0 c;
    public D d = new D(androidx.compose.runtime.snapshots.m.k().g());

    public E(M0 m0, Function0 function0) {
        this.b = function0;
        this.c = m0;
    }

    @Override // androidx.compose.runtime.snapshots.z
    public final void a(androidx.compose.runtime.snapshots.B b) {
        Intrinsics.e(b, "null cannot be cast to non-null type androidx.compose.runtime.DerivedSnapshotState.ResultRecord<T of androidx.compose.runtime.DerivedSnapshotState>");
        this.d = (D) b;
    }

    @Override // androidx.compose.runtime.snapshots.z
    public final androidx.compose.runtime.snapshots.B b() {
        return this.d;
    }

    @Override // androidx.compose.runtime.W0
    public final Object getValue() {
        Function1 function1E = androidx.compose.runtime.snapshots.m.k().e();
        if (function1E != null) {
            function1E.invoke(this);
        }
        androidx.compose.runtime.snapshots.h hVarK = androidx.compose.runtime.snapshots.m.k();
        return i((D) androidx.compose.runtime.snapshots.m.j(this.d, hVarK), hVarK, true, this.b).f;
    }

    public final D i(D d, androidx.compose.runtime.snapshots.h hVar, boolean z, Function0 function0) throws Throwable {
        D d2;
        M0 m0;
        boolean z2;
        boolean z3;
        int i;
        boolean z4 = true;
        if (!d.c(this, hVar)) {
            androidx.collection.C c = new androidx.collection.C();
            com.quizlet.data.repository.classfolder.e eVar = N0.a;
            androidx.compose.runtime.internal.f fVar = (androidx.compose.runtime.internal.f) eVar.c();
            if (fVar == null) {
                fVar = new androidx.compose.runtime.internal.f();
                eVar.q(fVar);
            }
            androidx.compose.runtime.internal.f fVar2 = fVar;
            int i2 = fVar2.a;
            androidx.compose.runtime.collection.b bVarO = C0776c.o();
            Object[] objArr = bVarO.a;
            int i3 = bVarO.c;
            for (int i4 = 0; i4 < i3; i4++) {
                ((C0812o) objArr[i4]).b();
            }
            try {
                fVar2.a = i2 + 1;
                Object objF = androidx.compose.runtime.snapshots.r.f(function0, new androidx.compose.foundation.text.X(i2, 3, this, fVar2, c));
                fVar2.a = i2;
                Object[] objArr2 = bVarO.a;
                int i5 = bVarO.c;
                for (int i6 = 0; i6 < i5; i6++) {
                    ((C0812o) objArr2[i6]).a();
                }
                Object obj = androidx.compose.runtime.snapshots.m.b;
                synchronized (obj) {
                    try {
                        androidx.compose.runtime.snapshots.h hVarK = androidx.compose.runtime.snapshots.m.k();
                        Object obj2 = d.f;
                        if (obj2 == D.h || (m0 = this.c) == null || !m0.a(objF, obj2)) {
                            D d3 = this.d;
                            synchronized (obj) {
                                androidx.compose.runtime.snapshots.B bM = androidx.compose.runtime.snapshots.m.m(d3, this);
                                bM.a(d3);
                                bM.a = hVarK.g();
                                d2 = (D) bM;
                                d2.e = c;
                                d2.g = d2.d(this, hVarK);
                                d2.f = objF;
                            }
                            return d2;
                        }
                        d.e = c;
                        d.g = d.d(this, hVarK);
                        d2 = d;
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                androidx.compose.runtime.internal.f fVar3 = (androidx.compose.runtime.internal.f) N0.a.c();
                if (fVar3 == null || fVar3.a != 0) {
                    return d2;
                }
                androidx.compose.runtime.snapshots.m.k().m();
                synchronized (obj) {
                    androidx.compose.runtime.snapshots.h hVarK2 = androidx.compose.runtime.snapshots.m.k();
                    d2.c = hVarK2.g();
                    d2.d = hVarK2.h();
                    Unit unit = Unit.a;
                    return d2;
                }
            } catch (Throwable th2) {
                Object[] objArr3 = bVarO.a;
                int i7 = bVarO.c;
                for (int i8 = 0; i8 < i7; i8++) {
                    ((C0812o) objArr3[i8]).a();
                }
                throw th2;
            }
        }
        if (z) {
            androidx.compose.runtime.collection.b bVarO2 = C0776c.o();
            Object[] objArr4 = bVarO2.a;
            int i9 = bVarO2.c;
            for (int i10 = 0; i10 < i9; i10++) {
                ((C0812o) objArr4[i10]).b();
            }
            try {
                androidx.collection.C c2 = d.e;
                com.quizlet.data.repository.classfolder.e eVar2 = N0.a;
                androidx.compose.runtime.internal.f fVar4 = (androidx.compose.runtime.internal.f) eVar2.c();
                if (fVar4 == null) {
                    fVar4 = new androidx.compose.runtime.internal.f();
                    eVar2.q(fVar4);
                }
                int i11 = fVar4.a;
                Object[] objArr5 = c2.b;
                int[] iArr = c2.c;
                long[] jArr = c2.a;
                int length = jArr.length - 2;
                if (length >= 0) {
                    int i12 = 0;
                    while (true) {
                        long j = jArr[i12];
                        Object[] objArr6 = objArr5;
                        if ((((~j) << 7) & j & (-9187201950435737472L)) != -9187201950435737472L) {
                            int i13 = 8;
                            int i14 = 8 - ((~(i12 - length)) >>> 31);
                            int i15 = 0;
                            while (i15 < i14) {
                                if ((j & 255) < 128) {
                                    int i16 = (i12 << 3) + i15;
                                    z3 = z4;
                                    try {
                                        androidx.compose.runtime.snapshots.z zVar = (androidx.compose.runtime.snapshots.z) objArr6[i16];
                                        i = i13;
                                        fVar4.a = i11 + iArr[i16];
                                        Function1 function1E = hVar.e();
                                        if (function1E != null) {
                                            function1E.invoke(zVar);
                                        }
                                    } catch (Throwable th3) {
                                        th = th3;
                                        Object[] objArr7 = bVarO2.a;
                                        int i17 = bVarO2.c;
                                        for (int i18 = 0; i18 < i17; i18++) {
                                            ((C0812o) objArr7[i18]).a();
                                        }
                                        throw th;
                                    }
                                } else {
                                    z3 = z4;
                                    i = i13;
                                }
                                j >>= i;
                                i15++;
                                i13 = i;
                                z4 = z3;
                            }
                            z2 = z4;
                            if (i14 != i13) {
                                break;
                            }
                        } else {
                            z2 = z4;
                        }
                        if (i12 == length) {
                            break;
                        }
                        i12++;
                        objArr5 = objArr6;
                        z4 = z2;
                    }
                }
                fVar4.a = i11;
                Unit unit2 = Unit.a;
                Object[] objArr8 = bVarO2.a;
                int i19 = bVarO2.c;
                for (int i20 = 0; i20 < i19; i20++) {
                    ((C0812o) objArr8[i20]).a();
                }
            } catch (Throwable th4) {
                th = th4;
            }
        }
        return d;
    }

    public final D j() {
        androidx.compose.runtime.snapshots.h hVarK = androidx.compose.runtime.snapshots.m.k();
        return i((D) androidx.compose.runtime.snapshots.m.j(this.d, hVarK), hVarK, false, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("DerivedState(value=");
        D d = (D) androidx.compose.runtime.snapshots.m.i(this.d);
        sb.append(d.c(this, androidx.compose.runtime.snapshots.m.k()) ? String.valueOf(d.f) : "<Not calculated>");
        sb.append(")@");
        sb.append(hashCode());
        return sb.toString();
    }
}
