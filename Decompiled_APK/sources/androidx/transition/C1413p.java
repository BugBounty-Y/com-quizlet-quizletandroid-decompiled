package androidx.transition;

import android.graphics.PorterDuffColorFilter;
import android.os.Build;
import android.view.View;
import android.view.ViewGroup;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.E0;
import androidx.compose.foundation.layout.G0;
import androidx.compose.foundation.layout.I0;
import androidx.compose.foundation.layout.K0;
import androidx.compose.material3.Q4;
import androidx.compose.material3.Z1;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0853m;
import androidx.compose.ui.graphics.C0854n;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.transition.C1413p;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.Z4;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Set;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.transition.p, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1413p implements InterfaceC1414q {
    public final /* synthetic */ int a = 1;

    public static final void c(final int i, final int i2, InterfaceC0806l interfaceC0806l, final androidx.compose.ui.q qVar) {
        int i3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1271987660);
        if ((i2 & 6) == 0) {
            i3 = (c0814p.d(i) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i3 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i3 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.e, false);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.ui.q qVarL = K0.l(androidx.compose.ui.n.b, com.quizlet.themes.m.W0, com.quizlet.themes.m.X0);
            androidx.compose.ui.graphics.painter.b bVarA = Z4.a(2131230904, c0814p, 0);
            long j = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).U0;
            AbstractC0460p.c(bVarA, AbstractC3106b5.d(c0814p, R.string.practice_test_results_score), qVarL, null, null, DefinitionKt.NO_Float_VALUE, new C0853m(j, 5, Build.VERSION.SDK_INT >= 29 ? C0854n.a.a(j, 5) : new PorterDuffColorFilter(androidx.compose.ui.graphics.F.A(j), androidx.compose.ui.graphics.F.E(5))), c0814p, 0, 56);
            c0814p = c0814p;
            g(0, 4, c0814p, null, AbstractC3106b5.d(c0814p, R.string.practice_test_results_score), AbstractC3106b5.c(R.string.practice_test_results_score_percentage, new Object[]{Integer.valueOf(i)}, c0814p));
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.features.practicetest.results.composables.f
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i2 | 1);
                    C1413p.c(i, iH, (InterfaceC0806l) obj, qVar);
                    return Unit.a;
                }
            };
        }
    }

    public static final void d(String str, int i, int i2, int i3, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i4) {
        int i5;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1627969337);
        if ((i4 & 6) == 0) {
            i5 = (c0814p.f(str) ? 4 : 2) | i4;
        } else {
            i5 = i4;
        }
        if ((i4 & 48) == 0) {
            i5 |= c0814p.d(i) ? 32 : 16;
        }
        if ((i4 & 384) == 0) {
            i5 |= c0814p.d(i2) ? 256 : 128;
        }
        if ((i4 & 3072) == 0) {
            i5 |= c0814p.d(i3) ? 2048 : 1024;
        }
        if ((i4 & 24576) == 0) {
            i5 |= c0814p.f(qVar) ? 16384 : 8192;
        }
        if ((i5 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarC = K0.c(qVar, 1.0f);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i6 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarC);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i6))) {
                android.support.v4.media.session.a.z(i6, c0814p, i6, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).e;
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            Q4.b(str, null, ((com.quizlet.themes.b) c0814p.j(b)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, i5 & 14, 0, 65530);
            c0814p = c0814p;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.p();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.j, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            mVar.c();
            Z1.c(qVarY, androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.h), Z1.o(((com.quizlet.themes.b) c0814p.j(b)).b.k(), 0L, 0L, c0814p, 0, 14), null, null, androidx.compose.runtime.internal.e.e(-1230015407, new com.quizlet.features.practicetest.results.composables.g(i, i2, i3), c0814p), c0814p, 196608, 24);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.practicetest.results.composables.d(str, i, i2, i3, qVar, i4, 1, (byte) 0);
        }
    }

    public static final void e(String str, String str2, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        String str3;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1597185169);
        int i2 = (c0814p2.f(str) ? 4 : 2) | i | (c0814p2.f(str2) ? 32 : 16);
        if ((i & 384) == 0) {
            i2 |= c0814p2.f(qVar) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            str3 = str2;
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.q qVarC = K0.c(qVar, 1.0f);
            G0 g0B = E0.b(AbstractC0398m.g, androidx.compose.ui.b.j, c0814p2, 6);
            int i3 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p2, qVarC);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, g0B, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p2, i3, c0912h);
            }
            C0776c.E(c0814p2, qVarC2, C0914j.d);
            androidx.compose.runtime.B b = com.quizlet.themes.w.a;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p2.j(b)).j;
            androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
            Q4.b(str, null, ((com.quizlet.themes.b) c0814p2.j(b2)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p2, i2 & 14, 0, 65530);
            str3 = str2;
            Q4.b(str3, null, ((com.quizlet.themes.b) c0814p2.j(b2)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(b)).f, c0814p2, (i2 >> 3) & 14, 0, 65530);
            c0814p = c0814p2;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.practicetest.results.composables.e(str, str3, qVar, i);
        }
    }

    public static final void f(String str, int i, int i2, int i3, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i4) {
        int i5;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1085041081);
        if ((i4 & 6) == 0) {
            i5 = (c0814p.f(str) ? 4 : 2) | i4;
        } else {
            i5 = i4;
        }
        if ((i4 & 48) == 0) {
            i5 |= c0814p.d(i) ? 32 : 16;
        }
        if ((i4 & 384) == 0) {
            i5 |= c0814p.d(i2) ? 256 : 128;
        }
        if ((i4 & 3072) == 0) {
            i5 |= c0814p.d(i3) ? 2048 : 1024;
        }
        if ((i4 & 24576) == 0) {
            i5 |= c0814p.f(qVar) ? 16384 : 8192;
        }
        if ((i5 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarC = K0.c(qVar, 1.0f);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i6 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarC);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, kE, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i6))) {
                android.support.v4.media.session.a.z(i6, c0814p, i6, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC2, c0912h4);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            int i7 = i5;
            androidx.compose.ui.q qVarQ = K0.q(K0.c(nVar, 1.0f), DefinitionKt.NO_Float_VALUE, com.quizlet.themes.m.U0, 1);
            G0 g0B = E0.b(AbstractC0398m.g, androidx.compose.ui.b.k, c0814p, 54);
            int i8 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, qVarQ);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i8))) {
                android.support.v4.media.session.a.z(i8, c0814p, i8, c0912h3);
            }
            C0776c.E(c0814p, qVarC3, c0912h4);
            I0 i0 = I0.a;
            Q4.b(str, i0.a(nVar, 1.0f, true), ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).d, c0814p, i7 & 14, 0, 65528);
            c0814p = c0814p;
            c(i, (i7 >> 3) & 14, c0814p, K0.t(i0.a(nVar, 0.8f, true), 2));
            g(0, 0, c0814p, K0.t(i0.a(nVar, 0.8f, true), 2), AbstractC3106b5.d(c0814p, R.string.practice_test_results), AbstractC3106b5.c(R.string.practice_test_results_fraction, new Object[]{Integer.valueOf(i2), Integer.valueOf(i3)}, c0814p));
            c0814p.p(true);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.practicetest.results.composables.d(str, i, i2, i3, qVar, i4, 2, (byte) 0);
        }
    }

    public static final void g(int i, int i2, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, String str, String str2) {
        androidx.compose.ui.q qVar2;
        int i3;
        androidx.compose.ui.q qVar3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(441349025);
        int i4 = i | (c0814p.f(str) ? 4 : 2) | (c0814p.f(str2) ? 32 : 16);
        int i5 = i2 & 4;
        if (i5 != 0) {
            i3 = i4 | 384;
            qVar2 = qVar;
        } else {
            qVar2 = qVar;
            i3 = i4 | (c0814p.f(qVar2) ? 256 : 128);
        }
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            qVar3 = qVar2;
        } else {
            androidx.compose.ui.q qVar4 = i5 != 0 ? androidx.compose.ui.n.b : qVar2;
            C0380d c0380d = AbstractC0398m.a;
            com.quizlet.themes.m.g.u();
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.g), androidx.compose.ui.b.m, c0814p, 0);
            int i6 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar4);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i6))) {
                android.support.v4.media.session.a.z(i6, c0814p, i6, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.runtime.B b = com.quizlet.themes.w.a;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(b)).i;
            androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
            androidx.compose.ui.q qVar5 = qVar4;
            Q4.b(str, null, ((com.quizlet.themes.b) c0814p.j(b2)).b.f(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, i3 & 14, 0, 65530);
            Q4.b(str2, null, ((com.quizlet.themes.b) c0814p.j(b2)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b)).d, c0814p, (i3 >> 3) & 14, 0, 65530);
            c0814p = c0814p;
            c0814p.p(true);
            qVar3 = qVar5;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.practicetest.results.composables.e(str, str2, qVar3, i, i2);
        }
    }

    public static final void h(String motivationalMessage, int i, int i2, int i3, androidx.compose.ui.q qVar, int i4, InterfaceC0806l interfaceC0806l, int i5) {
        int i6;
        int i7;
        int i8;
        Intrinsics.checkNotNullParameter(motivationalMessage, "motivationalMessage");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(210912101);
        int i9 = i5 | (c0814p.f(motivationalMessage) ? 4 : 2) | (c0814p.d(i) ? 32 : 16) | (c0814p.d(i2) ? 256 : 128) | (c0814p.d(i3) ? 2048 : 1024) | (c0814p.f(qVar) ? 16384 : 8192) | 65536;
        if ((74899 & i9) == 74898 && c0814p.x()) {
            c0814p.Q();
            i8 = i4;
        } else {
            c0814p.S();
            if ((i5 & 1) == 0 || c0814p.w()) {
                i6 = i9 & (-458753);
                i7 = AbstractC3205m5.g(c0814p).a;
            } else {
                c0814p.Q();
                i6 = i9 & (-458753);
                i7 = i4;
            }
            c0814p.q();
            Set set = androidx.compose.material3.windowsizeclass.c.b;
            if (i7 == 0) {
                c0814p.X(-1096567461);
                d(motivationalMessage, i, i2, i3, qVar, c0814p, i6 & 65534);
                c0814p.p(false);
            } else {
                c0814p.X(-1096329257);
                f(motivationalMessage, i, i2, i3, androidx.compose.ui.platform.N.G(qVar, "expanded"), c0814p, i6 & 8190);
                c0814p.p(false);
            }
            i8 = i7;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.practicetest.results.composables.d(motivationalMessage, i, i2, i3, qVar, i8, i5);
        }
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    public static okhttp3.L i(String javaName) {
        Intrinsics.checkNotNullParameter(javaName, "javaName");
        int iHashCode = javaName.hashCode();
        if (iHashCode != 79201641) {
            if (iHashCode != 79923350) {
                switch (iHashCode) {
                    case -503070503:
                        if (javaName.equals("TLSv1.1")) {
                            return okhttp3.L.TLS_1_1;
                        }
                        break;
                    case -503070502:
                        if (javaName.equals("TLSv1.2")) {
                            return okhttp3.L.TLS_1_2;
                        }
                        break;
                    case -503070501:
                        if (javaName.equals("TLSv1.3")) {
                            return okhttp3.L.TLS_1_3;
                        }
                        break;
                }
            } else if (javaName.equals("TLSv1")) {
                return okhttp3.L.TLS_1_0;
            }
        } else if (javaName.equals("SSLv3")) {
            return okhttp3.L.SSL_3_0;
        }
        throw new IllegalArgumentException("Unexpected TLS version: ".concat(javaName));
    }

    @Override // androidx.transition.InterfaceC1414q
    public float a(View view, ViewGroup viewGroup) {
        return view.getTranslationX();
    }

    @Override // androidx.transition.InterfaceC1414q
    public final float b(View view, ViewGroup viewGroup) {
        switch (this.a) {
            case 0:
                return view.getTranslationY() - viewGroup.getHeight();
            default:
                return view.getTranslationY() + viewGroup.getHeight();
        }
    }
}
