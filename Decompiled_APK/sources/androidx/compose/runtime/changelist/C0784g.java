package androidx.compose.runtime.changelist;

import androidx.compose.runtime.D0;
import androidx.compose.runtime.InterfaceC0790d;
import java.util.List;

/* renamed from: androidx.compose.runtime.changelist.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0784g extends J {
    public static final C0784g c = new C0784g(0, 2, 1);

    @Override // androidx.compose.runtime.changelist.J
    public final void a(K k, InterfaceC0790d interfaceC0790d, D0 d0, androidx.compose.runtime.internal.j jVar) {
        int i = ((androidx.compose.runtime.internal.f) k.f(0)).a;
        List list = (List) k.f(1);
        int size = list.size();
        for (int i2 = 0; i2 < size; i2++) {
            Object obj = list.get(i2);
            int i3 = i + i2;
            interfaceC0790d.c(i3, obj);
            interfaceC0790d.i(i3, obj);
        }
    }
}
