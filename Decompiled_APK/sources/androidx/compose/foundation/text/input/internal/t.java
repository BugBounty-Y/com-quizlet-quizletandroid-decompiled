package androidx.compose.foundation.text.input.internal;

import androidx.compose.ui.text.input.C1007j;
import androidx.compose.ui.text.input.InterfaceC1006i;

/* loaded from: classes.dex */
public final class t implements InterfaceC1006i {
    public final /* synthetic */ InterfaceC1006i[] a;

    public t(InterfaceC1006i[] interfaceC1006iArr) {
        this.a = interfaceC1006iArr;
    }

    @Override // androidx.compose.ui.text.input.InterfaceC1006i
    public final void a(C1007j c1007j) {
        for (InterfaceC1006i interfaceC1006i : this.a) {
            interfaceC1006i.a(c1007j);
        }
    }
}
