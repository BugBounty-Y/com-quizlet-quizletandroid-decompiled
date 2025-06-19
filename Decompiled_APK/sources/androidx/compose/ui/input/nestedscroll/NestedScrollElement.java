package androidx.compose.ui.input.nestedscroll;

import androidx.compose.ui.node.T;
import androidx.compose.ui.p;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class NestedScrollElement extends T {
    public final a b;
    public final e c;

    public NestedScrollElement(a aVar, e eVar) {
        this.b = aVar;
        this.c = eVar;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof NestedScrollElement)) {
            return false;
        }
        NestedScrollElement nestedScrollElement = (NestedScrollElement) obj;
        return Intrinsics.b(nestedScrollElement.b, this.b) && Intrinsics.b(nestedScrollElement.c, this.c);
    }

    public final int hashCode() {
        int iHashCode = this.b.hashCode() * 31;
        e eVar = this.c;
        return iHashCode + (eVar != null ? eVar.hashCode() : 0);
    }

    @Override // androidx.compose.ui.node.T
    public final p l() {
        return new i(this.b, this.c);
    }

    @Override // androidx.compose.ui.node.T
    public final void n(p pVar) {
        i iVar = (i) pVar;
        iVar.n = this.b;
        e eVar = iVar.o;
        if (eVar.a == iVar) {
            eVar.a = null;
        }
        e eVar2 = this.c;
        if (eVar2 == null) {
            iVar.o = new e();
        } else if (!eVar2.equals(eVar)) {
            iVar.o = eVar2;
        }
        if (iVar.m) {
            e eVar3 = iVar.o;
            eVar3.a = iVar;
            eVar3.b = new b(iVar, 1);
            eVar3.c = iVar.A0();
        }
    }
}
