package androidx.compose.foundation.text;

import androidx.compose.animation.C0293u;
import java.util.ArrayList;
import java.util.List;

/* renamed from: androidx.compose.foundation.text.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0487f implements androidx.compose.ui.layout.K {
    public static final C0487f b = new C0487f(0);
    public static final C0487f c = new C0487f(1);
    public final /* synthetic */ int a;

    public /* synthetic */ C0487f(int i) {
        this.a = i;
    }

    @Override // androidx.compose.ui.layout.K
    /* renamed from: measure-3p2s80s */
    public final androidx.compose.ui.layout.L mo1measure3p2s80s(androidx.compose.ui.layout.M m, List list, long j) {
        switch (this.a) {
            case 0:
                ArrayList arrayList = new ArrayList(list.size());
                int size = list.size();
                for (int i = 0; i < size; i++) {
                    arrayList.add(((androidx.compose.ui.layout.J) list.get(i)).B(j));
                }
                return m.n0(androidx.compose.ui.unit.a.h(j), androidx.compose.ui.unit.a.g(j), kotlin.collections.V.c(), new C0293u(1, arrayList));
            default:
                return m.n0(androidx.compose.ui.unit.a.h(j), androidx.compose.ui.unit.a.g(j), kotlin.collections.V.c(), C0491h.g);
        }
    }
}
