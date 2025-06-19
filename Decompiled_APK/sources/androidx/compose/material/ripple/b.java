package androidx.compose.material.ripple;

import android.view.View;
import androidx.collection.G;
import androidx.compose.animation.core.K;
import androidx.compose.material3.C0597c1;
import androidx.compose.material3.C0603d1;
import androidx.compose.ui.graphics.AbstractC0845e;
import androidx.compose.ui.graphics.InterfaceC0858s;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.InterfaceC0916l;
import androidx.compose.ui.node.InterfaceC0919o;
import androidx.compose.ui.node.InterfaceC0925v;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.google.android.gms.internal.mlkit_vision_barcode.G0;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import java.util.LinkedHashMap;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes.dex */
public final class b extends androidx.compose.ui.p implements i, InterfaceC0916l, InterfaceC0919o, InterfaceC0925v {
    public final androidx.compose.foundation.interaction.k n;
    public final boolean o;
    public final float p;
    public final C0597c1 q;
    public final C0603d1 r;
    public r s;
    public float t;
    public boolean v;
    public h x;
    public j y;
    public long u = 0;
    public final G w = new G();

    public b(androidx.compose.foundation.interaction.k kVar, boolean z, float f, C0597c1 c0597c1, C0603d1 c0603d1) {
        this.n = kVar;
        this.o = z;
        this.p = f;
        this.q = c0597c1;
        this.r = c0603d1;
    }

    @Override // androidx.compose.ui.p
    public final boolean B0() {
        return false;
    }

    @Override // androidx.compose.ui.p
    public final void E0() {
        E.A(A0(), null, null, new l(this, null), 3);
    }

    @Override // androidx.compose.ui.p
    public final void F0() {
        h hVar = this.x;
        if (hVar != null) {
            H();
            com.quizlet.data.interactor.school.b bVar = hVar.d;
            j jVar = (j) ((LinkedHashMap) bVar.b).get(this);
            if (jVar != null) {
                jVar.c();
                LinkedHashMap linkedHashMap = (LinkedHashMap) bVar.b;
                j jVar2 = (j) linkedHashMap.get(this);
                if (jVar2 != null) {
                }
                linkedHashMap.remove(this);
                hVar.c.add(jVar);
            }
        }
    }

    @Override // androidx.compose.material.ripple.i
    public final void H() {
        this.y = null;
        AbstractC0910f.n(this);
    }

    public final void M0(androidx.compose.foundation.interaction.q qVar) {
        if (!(qVar instanceof androidx.compose.foundation.interaction.o)) {
            if (qVar instanceof androidx.compose.foundation.interaction.p) {
                androidx.compose.foundation.interaction.o oVar = ((androidx.compose.foundation.interaction.p) qVar).a;
                j jVar = this.y;
                if (jVar != null) {
                    jVar.d();
                    return;
                }
                return;
            }
            if (qVar instanceof androidx.compose.foundation.interaction.n) {
                androidx.compose.foundation.interaction.o oVar2 = ((androidx.compose.foundation.interaction.n) qVar).a;
                j jVar2 = this.y;
                if (jVar2 != null) {
                    jVar2.d();
                    return;
                }
                return;
            }
            return;
        }
        androidx.compose.foundation.interaction.o oVar3 = (androidx.compose.foundation.interaction.o) qVar;
        long j = this.u;
        float f = this.t;
        h hVarA = this.x;
        if (hVarA == null) {
            hVarA = G0.a(G0.b((View) AbstractC0910f.i(this, AndroidCompositionLocals_androidKt.f)));
            this.x = hVarA;
            Intrinsics.d(hVarA);
        }
        j jVarA = hVarA.a(this);
        int iB = kotlin.math.c.b(f);
        long jA = this.q.a();
        this.r.invoke();
        jVarA.b(oVar3, this.o, j, iB, jA, 0.1f, new K(this, 19));
        this.y = jVarA;
        AbstractC0910f.n(this);
    }

    @Override // androidx.compose.ui.node.InterfaceC0919o
    public final void e(androidx.compose.ui.node.G g) {
        g.b();
        r rVar = this.s;
        if (rVar != null) {
            rVar.e(g, this.t, this.q.a());
        }
        InterfaceC0858s interfaceC0858sO = g.a.b.o();
        j jVar = this.y;
        if (jVar != null) {
            long j = this.u;
            int iB = kotlin.math.c.b(this.t);
            long jA = this.q.a();
            this.r.invoke();
            jVar.e(j, iB, jA, 0.1f);
            jVar.draw(AbstractC0845e.a(interfaceC0858sO));
        }
    }

    @Override // androidx.compose.ui.node.InterfaceC0925v
    public final void o(long j) {
        this.v = true;
        androidx.compose.ui.unit.b bVar = AbstractC0910f.v(this).r;
        this.u = R5.f(j);
        float f = this.p;
        this.t = Float.isNaN(f) ? g.a(bVar, this.o, this.u) : bVar.c0(f);
        G g = this.w;
        Object[] objArr = g.a;
        int i = g.b;
        for (int i2 = 0; i2 < i; i2++) {
            M0((androidx.compose.foundation.interaction.q) objArr[i2]);
        }
        C4930v.o(g.a, null, 0, g.b);
        g.b = 0;
    }
}
