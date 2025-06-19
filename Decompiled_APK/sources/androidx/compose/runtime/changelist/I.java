package androidx.compose.runtime.changelist;

import androidx.compose.runtime.D0;
import androidx.compose.runtime.InterfaceC0790d;
import androidx.compose.runtime.InterfaceC0802j;

/* loaded from: classes.dex */
public final class I extends J {
    public static final I c;

    static {
        int i = 0;
        c = new I(i, i, 3);
    }

    @Override // androidx.compose.runtime.changelist.J
    public final void a(K k, InterfaceC0790d interfaceC0790d, D0 d0, androidx.compose.runtime.internal.j jVar) {
        Object objL = interfaceC0790d.l();
        InterfaceC0802j interfaceC0802j = objL instanceof InterfaceC0802j ? (InterfaceC0802j) objL : null;
        if (interfaceC0802j != null) {
            interfaceC0802j.d();
        }
    }
}
