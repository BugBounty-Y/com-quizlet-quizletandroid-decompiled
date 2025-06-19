package androidx.compose.material3;

import androidx.compose.animation.core.C0238e;
import androidx.compose.animation.core.C0258o;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class Y {
    public final float a;
    public final float b;
    public final float c;
    public final float d;
    public final float e;
    public final float f;

    public Y(float f, float f2, float f3, float f4, float f5, float f6) {
        this.a = f;
        this.b = f2;
        this.c = f3;
        this.d = f4;
        this.e = f5;
        this.f = f6;
    }

    public final androidx.compose.runtime.W0 a(boolean z, androidx.compose.foundation.interaction.l lVar, InterfaceC0806l interfaceC0806l, int i) {
        C0238e c0238e;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1763481333);
        c0814p.X(-734838460);
        androidx.compose.runtime.V v = C0804k.a;
        float f = this.a;
        if (lVar == null) {
            Object objI = c0814p.I();
            if (objI == v) {
                objI = C0776c.z(new androidx.compose.ui.unit.e(f));
                c0814p.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objI;
            c0814p.p(false);
            c0814p.p(false);
            return interfaceC0773a0;
        }
        c0814p.p(false);
        Object objI2 = c0814p.I();
        if (objI2 == v) {
            objI2 = new androidx.compose.runtime.snapshots.q();
            c0814p.i0(objI2);
        }
        androidx.compose.runtime.snapshots.q qVar = (androidx.compose.runtime.snapshots.q) objI2;
        boolean z2 = true;
        boolean z3 = (((i & ContentType.LONG_FORM_ON_DEMAND) ^ 48) > 32 && c0814p.f(lVar)) || (i & 48) == 32;
        Object objI3 = c0814p.I();
        Object obj = null;
        if (z3 || objI3 == v) {
            objI3 = new W(lVar, qVar, null);
            c0814p.i0(objI3);
        }
        C0776c.f(c0814p, lVar, (Function2) objI3);
        androidx.compose.foundation.interaction.j jVar = (androidx.compose.foundation.interaction.j) CollectionsKt.V(qVar);
        if (!z) {
            f = this.f;
        } else if (jVar instanceof androidx.compose.foundation.interaction.o) {
            f = this.b;
        } else if (jVar instanceof androidx.compose.foundation.interaction.h) {
            f = this.d;
        } else if (jVar instanceof androidx.compose.foundation.interaction.d) {
            f = this.c;
        } else if (jVar instanceof androidx.compose.foundation.interaction.b) {
            f = this.e;
        }
        Object objI4 = c0814p.I();
        if (objI4 == v) {
            objI4 = new C0238e(new androidx.compose.ui.unit.e(f), androidx.compose.animation.core.M0.c, obj, 12);
            c0814p.i0(objI4);
        }
        C0238e c0238e2 = (C0238e) objI4;
        androidx.compose.ui.unit.e eVar = new androidx.compose.ui.unit.e(f);
        boolean zH = c0814p.h(c0238e2) | c0814p.c(f) | ((((i & 14) ^ 6) > 4 && c0814p.g(z)) || (i & 6) == 4);
        if ((((i & 896) ^ 384) <= 256 || !c0814p.f(this)) && (i & 384) != 256) {
            z2 = false;
        }
        boolean zH2 = zH | z2 | c0814p.h(jVar);
        Object objI5 = c0814p.I();
        if (zH2 || objI5 == v) {
            c0238e = c0238e2;
            X x = new X(c0238e, f, z, this, jVar, null);
            c0814p.i0(x);
            objI5 = x;
        } else {
            c0238e = c0238e2;
        }
        C0776c.f(c0814p, eVar, (Function2) objI5);
        C0258o c0258o = c0238e.c;
        c0814p.p(false);
        return c0258o;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !(obj instanceof Y)) {
            return false;
        }
        Y y = (Y) obj;
        return androidx.compose.ui.unit.e.a(this.a, y.a) && androidx.compose.ui.unit.e.a(this.b, y.b) && androidx.compose.ui.unit.e.a(this.c, y.c) && androidx.compose.ui.unit.e.a(this.d, y.d) && androidx.compose.ui.unit.e.a(this.f, y.f);
    }

    public final int hashCode() {
        return Float.hashCode(this.f) + android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(Float.hashCode(this.a) * 31, this.b, 31), this.c, 31), this.d, 31);
    }
}
