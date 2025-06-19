package androidx.compose.ui.node;

import androidx.compose.ui.layout.InterfaceC0894o;
import java.util.List;

/* loaded from: classes.dex */
public abstract class C implements androidx.compose.ui.layout.K {
    public final String a;

    public C(String str) {
        this.a = str;
    }

    @Override // androidx.compose.ui.layout.K
    public final int maxIntrinsicHeight(InterfaceC0894o interfaceC0894o, List list, int i) {
        throw new IllegalStateException(this.a.toString());
    }

    @Override // androidx.compose.ui.layout.K
    public final int maxIntrinsicWidth(InterfaceC0894o interfaceC0894o, List list, int i) {
        throw new IllegalStateException(this.a.toString());
    }

    @Override // androidx.compose.ui.layout.K
    public final int minIntrinsicHeight(InterfaceC0894o interfaceC0894o, List list, int i) {
        throw new IllegalStateException(this.a.toString());
    }

    @Override // androidx.compose.ui.layout.K
    public final int minIntrinsicWidth(InterfaceC0894o interfaceC0894o, List list, int i) {
        throw new IllegalStateException(this.a.toString());
    }
}
