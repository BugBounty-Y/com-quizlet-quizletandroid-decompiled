package androidx.compose.material3;

import androidx.compose.ui.layout.AbstractC0897s;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.O5;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class J2 implements androidx.compose.ui.layout.K {
    public final /* synthetic */ Function0 a;
    public final /* synthetic */ androidx.compose.runtime.internal.d b;
    public final /* synthetic */ boolean c;

    public J2(Function0 function0, androidx.compose.runtime.internal.d dVar, boolean z) {
        this.a = function0;
        this.b = dVar;
        this.c = z;
    }

    @Override // androidx.compose.ui.layout.K
    /* renamed from: measure-3p2s80s */
    public final androidx.compose.ui.layout.L mo1measure3p2s80s(androidx.compose.ui.layout.M m, List list, long j) {
        Object obj;
        androidx.compose.ui.layout.W wB;
        androidx.compose.ui.layout.W wB2;
        J2 j2 = this;
        float fFloatValue = ((Number) j2.a.invoke()).floatValue();
        long jA = androidx.compose.ui.unit.a.a(j, 0, 0, 0, 0, 10);
        int size = list.size();
        int i = 0;
        while (i < size) {
            androidx.compose.ui.layout.J j3 = (androidx.compose.ui.layout.J) list.get(i);
            if (Intrinsics.b(AbstractC0897s.h(j3), "icon")) {
                androidx.compose.ui.layout.W wB3 = j3.B(jA);
                char c = 2;
                float f = 2;
                int iM0 = m.m0(M2.d * f) + wB3.a;
                int iB = kotlin.math.c.b(iM0 * fFloatValue);
                int iM02 = m.m0(M2.e * f) + wB3.b;
                int size2 = list.size();
                int i2 = 0;
                while (i2 < size2) {
                    androidx.compose.ui.layout.J j4 = (androidx.compose.ui.layout.J) list.get(i2);
                    char c2 = c;
                    float f2 = fFloatValue;
                    if (Intrinsics.b(AbstractC0897s.h(j4), "indicatorRipple")) {
                        if (!(iM0 >= 0 && iM02 >= 0)) {
                            O5.e("width(" + iM0 + ") and height(" + iM02 + ") must be >= 0");
                            throw null;
                        }
                        float f3 = f;
                        androidx.compose.ui.layout.W wB4 = j4.B(L5.m(iM0, iM0, iM02, iM02));
                        int size3 = list.size();
                        int i3 = 0;
                        while (true) {
                            if (i3 >= size3) {
                                obj = null;
                                break;
                            }
                            obj = list.get(i3);
                            int i4 = size3;
                            int i5 = i3;
                            if (Intrinsics.b(AbstractC0897s.h((androidx.compose.ui.layout.J) obj), "indicator")) {
                                break;
                            }
                            i3 = i5 + 1;
                            size3 = i4;
                        }
                        androidx.compose.ui.layout.J j5 = (androidx.compose.ui.layout.J) obj;
                        if (j5 == null) {
                            wB = null;
                        } else {
                            if (iB < 0 || iM02 < 0) {
                                O5.e("width(" + iB + ") and height(" + iM02 + ") must be >= 0");
                                throw null;
                            }
                            wB = j5.B(L5.m(iB, iB, iM02, iM02));
                        }
                        androidx.compose.runtime.internal.d dVar = j2.b;
                        if (dVar != null) {
                            int size4 = list.size();
                            for (int i6 = 0; i6 < size4; i6++) {
                                androidx.compose.ui.layout.J j6 = (androidx.compose.ui.layout.J) list.get(i6);
                                if (Intrinsics.b(AbstractC0897s.h(j6), "label")) {
                                    wB2 = j6.B(jA);
                                }
                            }
                            throw new NoSuchElementException("Collection contains no element matching the predicate.");
                        }
                        wB2 = null;
                        if (dVar == null) {
                            int iH = androidx.compose.ui.unit.a.h(j);
                            int iK = L5.k(m.m0(M2.a), j);
                            return m.n0(iH, iK, kotlin.collections.V.c(), new K2(wB, wB3, (iH - wB3.a) / 2, (iK - wB3.b) / 2, wB4, (iH - wB4.a) / 2, (iK - wB4.b) / 2, iH, iK));
                        }
                        Intrinsics.d(wB2);
                        float f4 = wB3.b;
                        float f5 = M2.e;
                        float fC0 = m.c0(f5) + f4;
                        float f6 = M2.c;
                        float fC02 = m.c0(f6) + fC0 + wB2.b;
                        float fI = (androidx.compose.ui.unit.a.i(j) - fC02) / f3;
                        float fC03 = m.c0(f5);
                        if (fI < fC03) {
                            fI = fC03;
                        }
                        float f7 = (fI * f3) + fC02;
                        boolean z = j2.c;
                        float f8 = ((z ? fI : (f7 - wB3.b) / f3) - fI) * (1 - f2);
                        float fC04 = m.c0(f6) + m.c0(f5) + wB3.b + fI;
                        int iH2 = androidx.compose.ui.unit.a.h(j);
                        return m.n0(iH2, kotlin.math.c.b(f7), kotlin.collections.V.c(), new L2(wB, z, f2, wB2, (iH2 - wB2.a) / 2, fC04, f8, wB3, (iH2 - wB3.a) / 2, fI, wB4, (iH2 - wB4.a) / 2, fI - m.c0(f5), iH2, m));
                    }
                    i2++;
                    j2 = this;
                    c = c2;
                    fFloatValue = f2;
                    f = f;
                }
                throw new NoSuchElementException("Collection contains no element matching the predicate.");
            }
            i++;
            j2 = this;
        }
        throw new NoSuchElementException("Collection contains no element matching the predicate.");
    }
}
