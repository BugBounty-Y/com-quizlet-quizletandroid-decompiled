package androidx.compose.material3;

import androidx.compose.foundation.layout.InterfaceC0388h;
import androidx.compose.foundation.layout.InterfaceC0394k;
import androidx.compose.ui.layout.AbstractC0882c;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.layout.C0893n;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.material3.w, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0748w implements androidx.compose.ui.layout.K {
    public final /* synthetic */ InterfaceC0758x3 a;
    public final /* synthetic */ InterfaceC0388h b;
    public final /* synthetic */ InterfaceC0394k c;
    public final /* synthetic */ int d;

    public C0748w(InterfaceC0758x3 interfaceC0758x3, InterfaceC0388h interfaceC0388h, InterfaceC0394k interfaceC0394k, int i) {
        this.a = interfaceC0758x3;
        this.b = interfaceC0388h;
        this.c = interfaceC0394k;
        this.d = i;
    }

    @Override // androidx.compose.ui.layout.K
    /* renamed from: measure-3p2s80s */
    public final androidx.compose.ui.layout.L mo1measure3p2s80s(androidx.compose.ui.layout.M m, List list, long j) {
        int iH;
        int size = list.size();
        for (int i = 0; i < size; i++) {
            androidx.compose.ui.layout.J j2 = (androidx.compose.ui.layout.J) list.get(i);
            if (Intrinsics.b(AbstractC0897s.h(j2), "navigationIcon")) {
                androidx.compose.ui.layout.W wB = j2.B(androidx.compose.ui.unit.a.a(j, 0, 0, 0, 0, 14));
                int size2 = list.size();
                for (int i2 = 0; i2 < size2; i2++) {
                    androidx.compose.ui.layout.J j3 = (androidx.compose.ui.layout.J) list.get(i2);
                    if (Intrinsics.b(AbstractC0897s.h(j3), "actionIcons")) {
                        androidx.compose.ui.layout.W wB2 = j3.B(androidx.compose.ui.unit.a.a(j, 0, 0, 0, 0, 14));
                        if (androidx.compose.ui.unit.a.h(j) == Integer.MAX_VALUE) {
                            iH = androidx.compose.ui.unit.a.h(j);
                        } else {
                            iH = (androidx.compose.ui.unit.a.h(j) - wB.a) - wB2.a;
                            if (iH < 0) {
                                iH = 0;
                            }
                        }
                        int i3 = iH;
                        int size3 = list.size();
                        for (int i4 = 0; i4 < size3; i4++) {
                            androidx.compose.ui.layout.J j4 = (androidx.compose.ui.layout.J) list.get(i4);
                            if (Intrinsics.b(AbstractC0897s.h(j4), "title")) {
                                androidx.compose.ui.layout.W wB3 = j4.B(androidx.compose.ui.unit.a.a(j, 0, i3, 0, 0, 12));
                                C0893n c0893n = AbstractC0882c.b;
                                int iD0 = wB3.d0(c0893n) != Integer.MIN_VALUE ? wB3.d0(c0893n) : 0;
                                float fA = this.a.a();
                                int iG = androidx.compose.ui.unit.a.g(j) == Integer.MAX_VALUE ? androidx.compose.ui.unit.a.g(j) : androidx.compose.ui.unit.a.g(j) + (Float.isNaN(fA) ? 0 : kotlin.math.c.b(fA));
                                return m.n0(androidx.compose.ui.unit.a.h(j), iG, kotlin.collections.V.c(), new C0742v(wB, iG, wB3, this.b, j, wB2, m, this.c, this.d, iD0));
                            }
                        }
                        throw new NoSuchElementException("Collection contains no element matching the predicate.");
                    }
                }
                throw new NoSuchElementException("Collection contains no element matching the predicate.");
            }
        }
        throw new NoSuchElementException("Collection contains no element matching the predicate.");
    }
}
