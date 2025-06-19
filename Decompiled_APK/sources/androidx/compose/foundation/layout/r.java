package androidx.compose.foundation.layout;

import java.util.List;

/* loaded from: classes.dex */
public final class r implements androidx.compose.ui.layout.K {
    public static final r b = new r(0);
    public static final r c = new r(1);
    public final /* synthetic */ int a;

    public /* synthetic */ r(int i) {
        this.a = i;
    }

    @Override // androidx.compose.ui.layout.K
    /* renamed from: measure-3p2s80s */
    public final androidx.compose.ui.layout.L mo1measure3p2s80s(androidx.compose.ui.layout.M m, List list, long j) {
        switch (this.a) {
            case 0:
                return m.n0(androidx.compose.ui.unit.a.j(j), androidx.compose.ui.unit.a.i(j), kotlin.collections.V.c(), C0406q.b);
            default:
                return m.n0(androidx.compose.ui.unit.a.f(j) ? androidx.compose.ui.unit.a.h(j) : 0, androidx.compose.ui.unit.a.e(j) ? androidx.compose.ui.unit.a.g(j) : 0, kotlin.collections.V.c(), C0406q.h);
        }
    }
}
