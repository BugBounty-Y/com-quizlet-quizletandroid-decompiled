package androidx.compose.foundation;

/* loaded from: classes.dex */
public final class K0 extends androidx.compose.ui.p implements androidx.compose.ui.node.n0 {
    public N0 n;
    public boolean o;

    @Override // androidx.compose.ui.node.n0
    public final void r0(androidx.compose.ui.semantics.v vVar) {
        androidx.compose.ui.semantics.t.k(vVar);
        androidx.compose.ui.semantics.i iVar = new androidx.compose.ui.semantics.i(new J0(this, 0), new J0(this, 1));
        if (this.o) {
            androidx.compose.ui.semantics.u uVar = androidx.compose.ui.semantics.r.p;
            kotlin.reflect.n nVar = androidx.compose.ui.semantics.t.a[11];
            uVar.a(vVar, iVar);
        } else {
            androidx.compose.ui.semantics.u uVar2 = androidx.compose.ui.semantics.r.o;
            kotlin.reflect.n nVar2 = androidx.compose.ui.semantics.t.a[10];
            uVar2.a(vVar, iVar);
        }
    }
}
