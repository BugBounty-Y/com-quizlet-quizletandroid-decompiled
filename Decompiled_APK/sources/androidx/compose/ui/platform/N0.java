package androidx.compose.ui.platform;

import java.util.ArrayList;

/* loaded from: classes.dex */
public final class N0 implements androidx.compose.ui.node.h0 {
    public final int a;
    public final ArrayList b;
    public Float c = null;
    public Float d = null;
    public androidx.compose.ui.semantics.i e = null;
    public androidx.compose.ui.semantics.i f = null;

    public N0(int i, ArrayList arrayList) {
        this.a = i;
        this.b = arrayList;
    }

    @Override // androidx.compose.ui.node.h0
    public final boolean u() {
        return this.b.contains(this);
    }
}
