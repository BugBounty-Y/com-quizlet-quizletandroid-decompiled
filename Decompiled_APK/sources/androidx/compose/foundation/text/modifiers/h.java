package androidx.compose.foundation.text.modifiers;

import androidx.collection.z;
import androidx.compose.animation.d0;
import androidx.compose.foundation.lazy.layout.p0;
import androidx.compose.foundation.text.AbstractC0484d0;
import androidx.compose.foundation.text.selection.C;
import androidx.compose.foundation.text.selection.C0532m;
import androidx.compose.foundation.text.selection.Z;
import androidx.compose.foundation.text.selection.b0;
import androidx.compose.runtime.InterfaceC0834w0;
import androidx.compose.ui.input.pointer.SuspendPointerInputElement;
import androidx.compose.ui.input.pointer.v;
import androidx.compose.ui.q;

/* loaded from: classes.dex */
public final class h implements InterfaceC0834w0 {
    public final long a;
    public final Z b;
    public final long c;
    public j d;
    public C0532m e;
    public final q f;

    public h(long j, Z z, long j2) {
        j jVar = j.c;
        this.a = j;
        this.b = z;
        this.c = j2;
        this.d = jVar;
        g gVar = new g(this, 0);
        i iVar = new i(gVar, z, j);
        p0 p0Var = new p0();
        p0Var.c = gVar;
        p0Var.d = z;
        p0Var.b = j;
        p0Var.a = 0L;
        C c = new C(p0Var, iVar, null);
        androidx.compose.ui.input.pointer.f fVar = v.a;
        this.f = androidx.compose.ui.input.pointer.l.f(new SuspendPointerInputElement(p0Var, iVar, c, 4), AbstractC0484d0.b);
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void a() {
        C0532m c0532m = this.e;
        if (c0532m != null) {
            ((b0) this.b).d(c0532m);
            this.e = null;
        }
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void b() {
        C0532m c0532m = this.e;
        if (c0532m != null) {
            ((b0) this.b).d(c0532m);
            this.e = null;
        }
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void d() {
        g gVar = new g(this, 1);
        g gVar2 = new g(this, 2);
        long j = this.a;
        C0532m c0532m = new C0532m(j, gVar, gVar2);
        b0 b0Var = (b0) this.b;
        if (j == 0) {
            throw new IllegalArgumentException(d0.n(j, "The selectable contains an invalid id: ").toString());
        }
        z zVar = b0Var.c;
        if (zVar.a(j)) {
            throw new IllegalArgumentException(("Another selectable with the id: " + c0532m + ".selectableId has already subscribed.").toString());
        }
        zVar.f(j, c0532m);
        b0Var.b.add(c0532m);
        b0Var.a = false;
        this.e = c0532m;
    }
}
