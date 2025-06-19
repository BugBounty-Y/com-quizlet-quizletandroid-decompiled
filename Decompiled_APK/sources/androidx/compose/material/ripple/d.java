package androidx.compose.material.ripple;

import android.view.View;
import android.view.ViewGroup;
import androidx.compose.foundation.InterfaceC0369j0;
import androidx.compose.foundation.InterfaceC0371k0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.google.android.gms.internal.mlkit_vision_barcode.G0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class d implements InterfaceC0369j0 {
    public final boolean a;
    public final float b;
    public final InterfaceC0773a0 c;

    public d(boolean z, float f, InterfaceC0773a0 interfaceC0773a0) {
        this.a = z;
        this.b = f;
        this.c = interfaceC0773a0;
    }

    @Override // androidx.compose.foundation.InterfaceC0369j0
    public final InterfaceC0371k0 a(androidx.compose.foundation.interaction.k kVar, C0814p c0814p) {
        long jB;
        c0814p.X(988743187);
        m mVar = (m) c0814p.j(o.a);
        InterfaceC0773a0 interfaceC0773a0 = this.c;
        if (((C0861v) interfaceC0773a0.getValue()).a != 16) {
            c0814p.X(-303557454);
            c0814p.p(false);
            jB = ((C0861v) interfaceC0773a0.getValue()).a;
        } else {
            c0814p.X(-303499670);
            jB = mVar.b(c0814p);
            c0814p.p(false);
        }
        InterfaceC0773a0 interfaceC0773a0D = C0776c.D(new C0861v(jB), c0814p);
        InterfaceC0773a0 interfaceC0773a0D2 = C0776c.D(mVar.a(c0814p), c0814p);
        c0814p.X(331259447);
        ViewGroup viewGroupB = G0.b((View) c0814p.j(AndroidCompositionLocals_androidKt.f));
        boolean zF = c0814p.f(kVar) | c0814p.f(this) | c0814p.f(viewGroupB);
        Object objI = c0814p.I();
        Object obj = C0804k.a;
        if (zF || objI == obj) {
            Object aVar = new a(this.a, this.b, interfaceC0773a0D, interfaceC0773a0D2, viewGroupB);
            c0814p.i0(aVar);
            objI = aVar;
        }
        a aVar2 = (a) objI;
        c0814p.p(false);
        boolean zF2 = c0814p.f(kVar) | c0814p.h(aVar2);
        Object objI2 = c0814p.I();
        if (zF2 || objI2 == obj) {
            objI2 = new e(kVar, aVar2, null);
            c0814p.i0(objI2);
        }
        C0776c.g(aVar2, kVar, (Function2) objI2, c0814p);
        c0814p.p(false);
        return aVar2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a == dVar.a && androidx.compose.ui.unit.e.a(this.b, dVar.b) && this.c.equals(dVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + android.support.v4.media.session.a.b(Boolean.hashCode(this.a) * 31, this.b, 31);
    }
}
