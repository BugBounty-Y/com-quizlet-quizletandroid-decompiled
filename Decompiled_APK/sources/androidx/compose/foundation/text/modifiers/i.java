package androidx.compose.foundation.text.modifiers;

import androidx.compose.foundation.text.selection.C0537s;
import androidx.compose.foundation.text.selection.C0540v;
import androidx.compose.foundation.text.selection.Z;
import androidx.compose.foundation.text.selection.b0;
import androidx.compose.foundation.text.selection.c0;
import androidx.compose.foundation.text.u0;
import androidx.compose.ui.layout.r;

/* loaded from: classes.dex */
public final class i implements u0 {
    public long a = 0;
    public long b = 0;
    public final /* synthetic */ g c;
    public final /* synthetic */ Z d;
    public final /* synthetic */ long e;

    public i(g gVar, Z z, long j) {
        this.c = gVar;
        this.d = z;
        this.e = j;
    }

    @Override // androidx.compose.foundation.text.u0
    public final void a(long j) {
        r rVar = (r) this.c.invoke();
        Z z = this.d;
        if (rVar != null) {
            if (!rVar.k()) {
                return;
            }
            androidx.compose.foundation.text.selection.r rVar2 = C0537s.e;
            androidx.compose.foundation.lazy.f fVar = ((b0) z).f;
            if (fVar != null) {
                fVar.invoke(Boolean.TRUE, rVar, new androidx.compose.ui.geometry.b(j), rVar2);
            }
            this.a = j;
        }
        if (c0.a(z, this.e)) {
            this.b = 0L;
        }
    }

    @Override // androidx.compose.foundation.text.u0
    public final void b() {
    }

    @Override // androidx.compose.foundation.text.u0
    public final void c() {
    }

    @Override // androidx.compose.foundation.text.u0
    public final void d(long j) {
        r rVar = (r) this.c.invoke();
        if (rVar == null || !rVar.k()) {
            return;
        }
        Z z = this.d;
        if (c0.a(z, this.e)) {
            long jH = androidx.compose.ui.geometry.b.h(this.b, j);
            this.b = jH;
            long jH2 = androidx.compose.ui.geometry.b.h(this.a, jH);
            if (((b0) z).b(rVar, jH2, this.a, C0537s.e, true)) {
                this.a = jH2;
                this.b = 0L;
            }
        }
    }

    @Override // androidx.compose.foundation.text.u0
    public final void onCancel() {
        C0540v c0540v;
        Z z = this.d;
        if (!c0.a(z, this.e) || (c0540v = ((b0) z).h) == null) {
            return;
        }
        c0540v.invoke();
    }

    @Override // androidx.compose.foundation.text.u0
    public final void onStop() {
        C0540v c0540v;
        Z z = this.d;
        if (!c0.a(z, this.e) || (c0540v = ((b0) z).h) == null) {
            return;
        }
        c0540v.invoke();
    }
}
