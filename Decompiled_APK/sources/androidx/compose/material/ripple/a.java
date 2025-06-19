package androidx.compose.material.ripple;

import android.view.ViewGroup;
import androidx.compose.animation.core.K;
import androidx.compose.foundation.InterfaceC0371k0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0834w0;
import androidx.compose.runtime.L0;
import androidx.compose.ui.graphics.AbstractC0845e;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.InterfaceC0858s;
import androidx.compose.ui.node.G;
import java.util.LinkedHashMap;

/* loaded from: classes.dex */
public final class a implements InterfaceC0834w0, i, InterfaceC0371k0 {
    public final boolean a;
    public final r b;
    public final boolean c;
    public final float d;
    public final InterfaceC0773a0 e;
    public final InterfaceC0773a0 f;
    public final ViewGroup g;
    public h h;
    public final InterfaceC0773a0 i = C0776c.z(null);
    public final InterfaceC0773a0 j = C0776c.z(Boolean.TRUE);
    public long k = 0;
    public int l = -1;
    public final K m = new K(this, 18);

    public a(boolean z, float f, InterfaceC0773a0 interfaceC0773a0, InterfaceC0773a0 interfaceC0773a02, ViewGroup viewGroup) {
        this.a = z;
        this.b = new r(z, new androidx.compose.foundation.lazy.j(interfaceC0773a02, 5));
        this.c = z;
        this.d = f;
        this.e = interfaceC0773a0;
        this.f = interfaceC0773a02;
        this.g = viewGroup;
    }

    @Override // androidx.compose.material.ripple.i
    public final void H() {
        ((L0) this.i).setValue(null);
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void a() {
        h hVar = this.h;
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

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void b() {
        h hVar = this.h;
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

    @Override // androidx.compose.foundation.InterfaceC0371k0
    public final void c(G g) {
        int iM0;
        float fC0;
        androidx.compose.ui.graphics.drawscope.b bVar = g.a;
        this.k = bVar.g();
        float f = this.d;
        if (Float.isNaN(f)) {
            iM0 = kotlin.math.c.b(g.a(g, this.c, bVar.g()));
        } else {
            iM0 = bVar.m0(f);
        }
        this.l = iM0;
        long j = ((C0861v) this.e.getValue()).a;
        float f2 = ((f) this.f.getValue()).d;
        g.b();
        if (Float.isNaN(f)) {
            fC0 = g.a(g, this.a, bVar.g());
        } else {
            fC0 = g.c0(f);
        }
        this.b.e(g, fC0, j);
        InterfaceC0858s interfaceC0858sO = bVar.b.o();
        ((Boolean) ((L0) this.j).getValue()).booleanValue();
        j jVar = (j) ((L0) this.i).getValue();
        if (jVar != null) {
            jVar.e(bVar.g(), this.l, j, f2);
            jVar.draw(AbstractC0845e.a(interfaceC0858sO));
        }
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void d() {
    }
}
