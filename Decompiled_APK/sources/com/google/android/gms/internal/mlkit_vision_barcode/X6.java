package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0386g;
import androidx.compose.foundation.text.AbstractC0484d0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.text.C0984d;
import androidx.compose.ui.text.C0995g;
import com.quizlet.assembly.compose.buttons.C4093s;
import com.quizlet.assembly.compose.buttons.C4097w;
import com.quizlet.assembly.compose.buttons.InterfaceC4099y;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Set;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import kotlin.text.StringsKt;

/* loaded from: classes2.dex */
public abstract class X6 {
    public static final void a(com.quizlet.features.notes.data.f data, androidx.compose.ui.q qVar, Function1 function1, int i, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        int i4;
        float f;
        androidx.compose.ui.n nVar;
        androidx.compose.runtime.V v;
        boolean z;
        Intrinsics.checkNotNullParameter(data, "data");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-962770257);
        int i5 = i2 | (c0814p.h(data) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16) | (c0814p.h(function1) ? 256 : 128) | 1024;
        if ((i5 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            int i6 = i2 & 1;
            androidx.compose.runtime.V v2 = C0804k.a;
            if (i6 == 0 || c0814p.w()) {
                i3 = i5 & (-7169);
                i4 = AbstractC3205m5.g(c0814p).a;
            } else {
                c0814p.Q();
                i3 = i5 & (-7169);
                i4 = i;
            }
            c0814p.q();
            androidx.compose.ui.g gVar = androidx.compose.ui.b.n;
            C0386g c0386g = AbstractC0398m.e;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.i;
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(AbstractC0382e.u(qVar, f2).g(androidx.compose.foundation.layout.K0.c), "errorContent");
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(c0386g, gVar, c0814p, 54);
            int i7 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i7))) {
                android.support.v4.media.session.a.z(i7, c0814p, i7, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            String strD = AbstractC3106b5.d(c0814p, R.string.scan_notes_title);
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            mVar.l();
            AbstractC0460p.c(data.f, strD, androidx.compose.foundation.layout.K0.k(nVar2, com.quizlet.ui.resources.designsystem.generated.h.k), null, null, DefinitionKt.NO_Float_VALUE, null, c0814p, 0, 120);
            androidx.compose.runtime.B b = com.quizlet.themes.w.a;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(b)).f;
            androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
            long jE = ((com.quizlet.themes.b) c0814p.j(b2)).b.e();
            mVar.q();
            androidx.compose.material3.Q4.b(data.a, AbstractC0382e.y(nVar2, DefinitionKt.NO_Float_VALUE, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), jE, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65016);
            c0814p = c0814p;
            c0814p.X(608226938);
            String str = data.c;
            if (str == null) {
                i = i4;
                z = false;
                v = v2;
                f = f2;
                nVar = nVar2;
            } else {
                String strD2 = AbstractC3106b5.d(c0814p, R.string.user_settings_help_center);
                String strD3 = AbstractC3106b5.d(c0814p, R.string.user_settings_terms_of_service);
                c0814p.X(608236095);
                C0984d c0984d = new C0984d();
                int i8 = c0984d.i(new androidx.compose.ui.text.D(((com.quizlet.themes.b) c0814p.j(b2)).b.e(), 0L, (androidx.compose.ui.text.font.u) null, (androidx.compose.ui.text.font.q) null, (androidx.compose.ui.text.font.r) null, (androidx.compose.ui.text.font.j) null, (String) null, 0L, (androidx.compose.ui.text.style.a) null, (androidx.compose.ui.text.style.o) null, (androidx.compose.ui.text.intl.b) null, 0L, (androidx.compose.ui.text.style.j) null, (androidx.compose.ui.graphics.U) null, 65534));
                try {
                    c0984d.f(str);
                    Unit unit = Unit.a;
                    c0984d.h(i8);
                    int iM = StringsKt.M(str, strD2, 0, true, 2);
                    int length = strD2.length() + iM;
                    c0814p.X(608248693);
                    if (iM < 0 || length <= 0) {
                        i = i4;
                    } else {
                        i = i4;
                        c0984d.c(new androidx.compose.ui.text.D(((com.quizlet.themes.b) c0814p.j(b2)).e, 0L, (androidx.compose.ui.text.font.u) null, (androidx.compose.ui.text.font.q) null, (androidx.compose.ui.text.font.r) null, (androidx.compose.ui.text.font.j) null, (String) null, 0L, (androidx.compose.ui.text.style.a) null, (androidx.compose.ui.text.style.o) null, (androidx.compose.ui.text.intl.b) null, 0L, (androidx.compose.ui.text.style.j) null, (androidx.compose.ui.graphics.U) null, 65534), iM, length);
                        c0984d.b("helpCenter", iM, "helpCenter", length);
                    }
                    c0814p.p(false);
                    int iM2 = StringsKt.M(str, strD3, 0, true, 2);
                    int length2 = strD3.length() + iM2;
                    c0814p.X(608276567);
                    if (iM2 >= 0 && length2 > 0) {
                        c0984d.c(new androidx.compose.ui.text.D(((com.quizlet.themes.b) c0814p.j(b2)).e, 0L, (androidx.compose.ui.text.font.u) null, (androidx.compose.ui.text.font.q) null, (androidx.compose.ui.text.font.r) null, (androidx.compose.ui.text.font.j) null, (String) null, 0L, (androidx.compose.ui.text.style.a) null, (androidx.compose.ui.text.style.o) null, (androidx.compose.ui.text.intl.b) null, 0L, (androidx.compose.ui.text.style.j) null, (androidx.compose.ui.graphics.U) null, 65534), iM2, length2);
                        c0984d.b("termsOfService", iM2, "termsOfService", length2);
                    }
                    c0814p.p(false);
                    C0995g c0995gJ = c0984d.j();
                    c0814p.p(false);
                    androidx.compose.ui.text.L lB = androidx.compose.ui.text.L.b(((com.quizlet.themes.f) c0814p.j(b)).o, 0L, 0L, null, null, 0L, 3, 0L, null, 16744447);
                    mVar.q();
                    f = f2;
                    androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar2, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
                    nVar = nVar2;
                    c0814p.X(-1615435841);
                    boolean zF = c0814p.f(c0995gJ) | ((i3 & 896) == 256);
                    Object objI = c0814p.I();
                    if (zF) {
                        v = v2;
                    } else {
                        v = v2;
                        if (objI == v) {
                        }
                        c0814p.p(false);
                        z = false;
                        AbstractC0484d0.c(c0995gJ, qVarY, lB, false, 0, 0, null, (Function1) objI, c0814p, 0);
                        c0814p = c0814p;
                    }
                    objI = new androidx.lifecycle.u0(23, (Object) c0995gJ, (Object) function1);
                    c0814p.i0(objI);
                    c0814p.p(false);
                    z = false;
                    AbstractC0484d0.c(c0995gJ, qVarY, lB, false, 0, 0, null, (Function1) objI, c0814p, 0);
                    c0814p = c0814p;
                } catch (Throwable th) {
                    c0984d.h(i8);
                    throw th;
                }
            }
            c0814p.p(z);
            c0814p.X(608321424);
            if (data.d) {
                Set set = androidx.compose.material3.windowsizeclass.c.b;
                InterfaceC4099y interfaceC4099y = i == 0 ? C4093s.a : C4097w.a;
                androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(androidx.compose.foundation.layout.K0.q(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.themes.m.F, 1), 1.0f);
                mVar.q();
                androidx.compose.ui.q qVarY2 = AbstractC0382e.y(qVarC2, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
                c0814p.X(608324798);
                boolean zH = c0814p.h(data) | ((i3 & 896) == 256 ? true : z);
                Object objI2 = c0814p.I();
                if (zH || objI2 == v) {
                    objI2 = new com.quizlet.data.repository.explanations.exercise.a(21, function1, data);
                    c0814p.i0(objI2);
                }
                c0814p.p(z);
                C0814p c0814p2 = c0814p;
                com.google.android.gms.internal.mlkit_vision_document_scanner.W4.a(data.b, qVarY2, (Function0) objI2, false, null, interfaceC4099y, null, null, null, false, c0814p2, 0, 984);
                c0814p = c0814p2;
            }
            c0814p.p(z);
            c0814p.p(true);
        }
        int i9 = i;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i9, i2, 16, qVar, (Object) data, (Object) function1);
        }
    }

    public static final Charset b(io.ktor.http.d dVar) {
        String name;
        Intrinsics.checkNotNullParameter(dVar, "<this>");
        dVar.getClass();
        Intrinsics.checkNotNullParameter("charset", "name");
        List list = (List) dVar.c;
        int i = kotlin.collections.B.i(list);
        if (i >= 0) {
            int i2 = 0;
            while (true) {
                io.ktor.http.h hVar = (io.ktor.http.h) list.get(i2);
                if (!kotlin.text.D.l(hVar.a, "charset", true)) {
                    if (i2 == i) {
                        break;
                    }
                    i2++;
                } else {
                    name = hVar.b;
                    break;
                }
            }
            name = null;
        } else {
            name = null;
        }
        if (name != null) {
            try {
                Intrinsics.checkNotNullParameter(Charsets.a, "<this>");
                Intrinsics.checkNotNullParameter(name, "name");
                Charset charsetForName = Charset.forName(name);
                Intrinsics.checkNotNullExpressionValue(charsetForName, "forName(...)");
                return charsetForName;
            } catch (IllegalArgumentException unused) {
            }
        }
        return null;
    }

    public abstract void c(Throwable th);

    public abstract void d(com.quizlet.data.repository.explanations.textbook.a aVar);
}
