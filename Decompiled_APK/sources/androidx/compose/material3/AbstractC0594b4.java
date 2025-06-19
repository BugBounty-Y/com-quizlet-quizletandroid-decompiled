package androidx.compose.material3;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.C0555x;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0811n0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;

/* renamed from: androidx.compose.material3.b4, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0594b4 {
    public static final androidx.compose.runtime.B a = new androidx.compose.runtime.B(C0584a0.r);

    public static final void a(androidx.compose.ui.q qVar, androidx.compose.ui.graphics.V v, long j, long j2, float f, float f2, C0555x c0555x, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i, int i2) {
        if ((i2 & 2) != 0) {
            v = androidx.compose.ui.graphics.F.a;
        }
        if ((i2 & 4) != 0) {
            j = ((Z) ((C0814p) interfaceC0806l).j(AbstractC0590b0.a)).p;
        }
        if ((i2 & 8) != 0) {
            j2 = AbstractC0590b0.b(j, interfaceC0806l);
        }
        if ((i2 & 16) != 0) {
            f = 0;
        }
        if ((i2 & 32) != 0) {
            f2 = 0;
        }
        if ((i2 & 64) != 0) {
            c0555x = null;
        }
        C0814p c0814p = (C0814p) interfaceC0806l;
        androidx.compose.runtime.B b = a;
        float f3 = ((androidx.compose.ui.unit.e) c0814p.j(b)).a + f;
        C0776c.b(new C0811n0[]{androidx.compose.animation.d0.j(j2, AbstractC0669k0.a), b.a(new androidx.compose.ui.unit.e(f3))}, androidx.compose.runtime.internal.e.e(-70914509, new X3(qVar, v, j, f3, c0555x, f2, dVar), c0814p), c0814p, 56);
    }

    public static final void b(boolean z, Function0 function0, androidx.compose.ui.q qVar, boolean z2, androidx.compose.ui.graphics.V v, long j, long j2, C0555x c0555x, androidx.compose.foundation.interaction.l lVar, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i, int i2) {
        long jB = (i2 & 64) != 0 ? AbstractC0590b0.b(j, interfaceC0806l) : j2;
        float f = 0;
        float f2 = 0;
        C0555x c0555x2 = (i2 & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0 ? null : c0555x;
        androidx.compose.foundation.interaction.l lVar2 = (i2 & 1024) != 0 ? null : lVar;
        C0814p c0814p = (C0814p) interfaceC0806l;
        androidx.compose.runtime.B b = a;
        float f3 = ((androidx.compose.ui.unit.e) c0814p.j(b)).a + f;
        C0776c.b(new C0811n0[]{androidx.compose.animation.d0.j(jB, AbstractC0669k0.a), b.a(new androidx.compose.ui.unit.e(f3))}, androidx.compose.runtime.internal.e.e(-1164547968, new Z3(qVar, v, j, f3, c0555x2, z, lVar2, z2, function0, f2, dVar), c0814p), c0814p, 56);
    }

    public static final void c(Function0 function0, androidx.compose.ui.q qVar, boolean z, androidx.compose.ui.graphics.V v, long j, long j2, float f, float f2, C0555x c0555x, androidx.compose.foundation.interaction.l lVar, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i, int i2) {
        boolean z2 = (i2 & 4) != 0 ? true : z;
        long jB = (i2 & 32) != 0 ? AbstractC0590b0.b(j, interfaceC0806l) : j2;
        float f3 = (i2 & 64) != 0 ? 0 : f;
        float f4 = (i2 & 128) != 0 ? 0 : f2;
        C0555x c0555x2 = (i2 & 256) != 0 ? null : c0555x;
        C0814p c0814p = (C0814p) interfaceC0806l;
        androidx.compose.runtime.B b = a;
        float f5 = ((androidx.compose.ui.unit.e) c0814p.j(b)).a + f3;
        C0776c.b(new C0811n0[]{androidx.compose.animation.d0.j(jB, AbstractC0669k0.a), b.a(new androidx.compose.ui.unit.e(f5))}, androidx.compose.runtime.internal.e.e(1279702876, new Y3(qVar, v, j, f5, c0555x2, lVar, z2, function0, f4, dVar), c0814p), c0814p, 56);
    }

    public static final androidx.compose.ui.q d(androidx.compose.ui.q qVar, androidx.compose.ui.graphics.V v, long j, C0555x c0555x, float f) {
        androidx.compose.ui.graphics.V v2;
        androidx.compose.ui.q qVarQ;
        androidx.compose.ui.q qVarH = androidx.compose.ui.n.b;
        if (f > DefinitionKt.NO_Float_VALUE) {
            v2 = v;
            qVarQ = androidx.compose.ui.graphics.F.q(qVarH, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, v2, false, 124895);
        } else {
            v2 = v;
            qVarQ = qVarH;
        }
        androidx.compose.ui.q qVarG = qVar.g(qVarQ);
        if (c0555x != null) {
            qVarH = AbstractC0460p.h(qVarH, c0555x.a, c0555x.b, v2);
        }
        return androidx.compose.ui.draw.g.c(AbstractC0460p.f(qVarG.g(qVarH), j, v2), v2);
    }

    public static final long e(long j, float f, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        Z z = (Z) c0814p.j(AbstractC0590b0.a);
        boolean zBooleanValue = ((Boolean) c0814p.j(AbstractC0590b0.b)).booleanValue();
        if (!C0861v.c(j, z.p) || !zBooleanValue) {
            return j;
        }
        boolean zA = androidx.compose.ui.unit.e.a(f, 0);
        long j2 = z.p;
        if (zA) {
            return j2;
        }
        return androidx.compose.ui.graphics.F.m(C0861v.b(z.t, ((((float) Math.log(f + 1)) * 4.5f) + 2.0f) / 100.0f), j2);
    }
}
