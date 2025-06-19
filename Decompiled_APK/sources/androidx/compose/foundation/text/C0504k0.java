package androidx.compose.foundation.text;

import androidx.compose.animation.C0278e;
import androidx.compose.material3.AbstractC0709q4;
import androidx.compose.material3.C0697o4;
import androidx.compose.ui.layout.AbstractC0882c;
import androidx.compose.ui.layout.AbstractC0897s;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.InterfaceC4938g;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.text.k0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0504k0 implements androidx.compose.ui.layout.K {
    public final /* synthetic */ int a;
    public final InterfaceC4938g b;

    public /* synthetic */ C0504k0(InterfaceC4938g interfaceC4938g, int i) {
        this.a = i;
        this.b = interfaceC4938g;
    }

    @Override // androidx.compose.ui.layout.K
    /* renamed from: measure-3p2s80s */
    public final androidx.compose.ui.layout.L mo1measure3p2s80s(androidx.compose.ui.layout.M m, List list, long j) {
        androidx.compose.ui.layout.W wB;
        switch (this.a) {
            case 0:
                return m.n0(androidx.compose.ui.unit.a.h(j), androidx.compose.ui.unit.a.g(j), kotlin.collections.V.c(), new C0278e(21, list, this));
            default:
                if (((androidx.compose.runtime.internal.d) this.b) != null) {
                    int size = list.size();
                    for (int i = 0; i < size; i++) {
                        androidx.compose.ui.layout.J j2 = (androidx.compose.ui.layout.J) list.get(i);
                        if (Intrinsics.b(AbstractC0897s.h(j2), "text")) {
                            wB = j2.B(androidx.compose.ui.unit.a.a(j, 0, 0, 0, 0, 11));
                        }
                    }
                    throw new NoSuchElementException("Collection contains no element matching the predicate.");
                }
                wB = null;
                int iMax = Math.max(wB != null ? wB.a : 0, 0);
                int iMax2 = Math.max(m.m0(AbstractC0709q4.a), m.j0(AbstractC0709q4.e) + 0 + (wB != null ? wB.b : 0));
                return m.n0(iMax, iMax2, kotlin.collections.V.c(), new C0697o4(wB, null, m, iMax, iMax2, wB != null ? Integer.valueOf(wB.d0(AbstractC0882c.a)) : null, wB != null ? Integer.valueOf(wB.d0(AbstractC0882c.b)) : null));
        }
    }
}
