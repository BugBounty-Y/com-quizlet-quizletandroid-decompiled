package androidx.compose.ui.layout;

import androidx.compose.ui.node.AbstractC0910f;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class O implements K {
    public final N a;

    public O(N n) {
        this.a = n;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof O) && Intrinsics.b(this.a, ((O) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    @Override // androidx.compose.ui.layout.K
    public final int maxIntrinsicHeight(InterfaceC0894o interfaceC0894o, List list, int i) {
        return this.a.maxIntrinsicHeight(interfaceC0894o, AbstractC0910f.l(interfaceC0894o), i);
    }

    @Override // androidx.compose.ui.layout.K
    public final int maxIntrinsicWidth(InterfaceC0894o interfaceC0894o, List list, int i) {
        return this.a.maxIntrinsicWidth(interfaceC0894o, AbstractC0910f.l(interfaceC0894o), i);
    }

    @Override // androidx.compose.ui.layout.K
    /* renamed from: measure-3p2s80s */
    public final L mo1measure3p2s80s(M m, List list, long j) {
        return this.a.mo2measure3p2s80s(m, AbstractC0910f.l(m), j);
    }

    @Override // androidx.compose.ui.layout.K
    public final int minIntrinsicHeight(InterfaceC0894o interfaceC0894o, List list, int i) {
        return this.a.minIntrinsicHeight(interfaceC0894o, AbstractC0910f.l(interfaceC0894o), i);
    }

    @Override // androidx.compose.ui.layout.K
    public final int minIntrinsicWidth(InterfaceC0894o interfaceC0894o, List list, int i) {
        return this.a.minIntrinsicWidth(interfaceC0894o, AbstractC0910f.l(interfaceC0894o), i);
    }

    public final String toString() {
        return "MultiContentMeasurePolicyImpl(measurePolicy=" + this.a + ')';
    }
}
