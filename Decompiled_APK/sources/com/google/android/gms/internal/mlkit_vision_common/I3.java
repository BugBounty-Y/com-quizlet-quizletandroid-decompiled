package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.LayoutWeightElement;
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
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_common.I3;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class I3 {
    public static final void a(long j, com.quizlet.features.infra.models.a aVar, Boolean bool, boolean z, String str, String str2, Function2 function2, kotlin.jvm.functions.d dVar, kotlin.jvm.functions.c cVar, com.quizlet.features.infra.models.a aVar2, String str3, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(2076526813);
        int i2 = i | (c0814p.e(j) ? 4 : 2) | (c0814p.f(aVar) ? 32 : 16) | (c0814p.f(bool) ? 256 : 128) | (c0814p.g(z) ? 2048 : 1024) | (c0814p.f(str) ? 16384 : 8192) | (c0814p.f(str2) ? 131072 : 65536) | (c0814p.h(function2) ? 1048576 : 524288) | (c0814p.h(dVar) ? 8388608 : 4194304) | (c0814p.h(cVar) ? 67108864 : 33554432) | (c0814p.f(aVar2) ? 536870912 : 268435456);
        int i3 = c0814p.f(str3) ? 4 : 2;
        if ((306783379 & i2) == 306783378 && (i3 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.ui.q qVarU = AbstractC0382e.u(nVar, f);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarU);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, bA, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.e, androidx.compose.ui.b.j, c0814p, 54);
            int i5 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, qVarC2);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h3);
            }
            C0776c.E(c0814p, qVarC3, c0912h4);
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            int i6 = i2 << 3;
            int i7 = i2 & 7168;
            int i8 = i2 & 57344;
            L3.a(aVar, j, androidx.compose.ui.platform.N.G(new LayoutWeightElement(1.0f > Float.MAX_VALUE ? Float.MAX_VALUE : 1.0f, true), "term_section"), z, str, cVar, c0814p, ((i2 >> 3) & 14) | (i6 & ContentType.LONG_FORM_ON_DEMAND) | i7 | i8 | ((i2 >> 9) & 458752));
            int i9 = i2 & 14;
            K3.a(j, androidx.compose.ui.platform.N.G(nVar, "term_button_section"), bool, z, str, str2, function2, dVar, c0814p, i9 | 48 | (i2 & 896) | i7 | i8 | (i2 & 458752) | (i2 & 3670016) | (29360128 & i2));
            c0814p.p(true);
            mVar.s();
            AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.d(nVar, f));
            int i10 = i2 >> 6;
            J3.a(j, aVar2, str3, str2, z, androidx.compose.ui.platform.N.G(nVar, "definition_section"), cVar, c0814p, i9 | 196608 | ((i2 >> 24) & ContentType.LONG_FORM_ON_DEMAND) | ((i3 << 6) & 896) | (i10 & 7168) | (i6 & 57344) | (i10 & 3670016));
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.termlist.ui.b(j, aVar, bool, z, str, str2, function2, dVar, cVar, aVar2, str3, i, 0);
        }
    }

    public static final void b(long j, com.quizlet.features.infra.models.a aVar, Boolean bool, boolean z, String str, String str2, Function2 function2, kotlin.jvm.functions.d dVar, kotlin.jvm.functions.c cVar, com.quizlet.features.infra.models.a aVar2, String str3, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-949166065);
        int i2 = i | (c0814p.e(j) ? 4 : 2) | (c0814p.f(aVar) ? 32 : 16) | (c0814p.f(bool) ? 256 : 128) | (c0814p.g(z) ? 2048 : 1024) | (c0814p.f(str) ? 16384 : 8192) | (c0814p.f(str2) ? 131072 : 65536) | (c0814p.h(function2) ? 1048576 : 524288) | (c0814p.h(dVar) ? 8388608 : 4194304) | (c0814p.h(cVar) ? 67108864 : 33554432) | (c0814p.f(aVar2) ? 536870912 : 268435456);
        int i3 = c0814p.f(str3) ? 4 : 2;
        if ((306783379 & i2) == 306783378 && (i3 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.ui.q qVarU = AbstractC0382e.u(nVar, f);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.j, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarU);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.foundation.layout.I0 i0 = androidx.compose.foundation.layout.I0.a;
            int i5 = i2 << 3;
            int i6 = i2 & 7168;
            int i7 = i2 & 57344;
            L3.a(aVar, j, androidx.compose.ui.platform.N.G(i0.a(nVar, 1.0f, true), "term_section"), z, str, cVar, c0814p, ((i2 >> 3) & 14) | (i5 & ContentType.LONG_FORM_ON_DEMAND) | i6 | i7 | ((i2 >> 9) & 458752));
            long jI = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.i();
            mVar.u();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.g;
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(nVar, "definition_section");
            mVar.s();
            androidx.compose.ui.q qVarA = i0.a(AbstractC0382e.y(qVarG, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 14), 1.0f, true);
            c0814p.X(1883490230);
            boolean zC = c0814p.c(f2) | c0814p.e(jI);
            Object objI = c0814p.I();
            if (zC || objI == C0804k.a) {
                objI = new com.braze.requests.framework.m(jI);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            int i8 = i2 & 14;
            int i9 = i2 >> 6;
            J3.a(j, aVar2, str3, str2, z, androidx.compose.ui.draw.g.e(qVarA, (Function1) objI), cVar, c0814p, ((i2 >> 24) & ContentType.LONG_FORM_ON_DEMAND) | i8 | ((i3 << 6) & 896) | (i9 & 7168) | (i5 & 57344) | (i9 & 3670016));
            K3.a(j, androidx.compose.ui.platform.N.G(nVar, "term_button_section"), bool, z, str, str2, function2, dVar, c0814p, i8 | 48 | (i2 & 896) | i6 | i7 | (i2 & 458752) | (i2 & 3670016) | (29360128 & i2));
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.termlist.ui.b(j, aVar, bool, z, str, str2, function2, dVar, cVar, aVar2, str3, i, 1);
        }
    }

    public static final void c(final long j, final com.quizlet.features.infra.models.a termContentTextData, final com.quizlet.features.infra.models.a aVar, final Boolean bool, final String str, final String str2, final String str3, final boolean z, androidx.compose.ui.q qVar, final Function2 function2, final kotlin.jvm.functions.d dVar, final kotlin.jvm.functions.c cVar, int i, InterfaceC0806l interfaceC0806l, final int i2, final int i3, final int i4) {
        int i5;
        Boolean bool2;
        String str4;
        String str5;
        androidx.compose.ui.q qVar2;
        int i6;
        int i7;
        androidx.compose.ui.q qVar3;
        int i8;
        final int i9;
        final androidx.compose.ui.q qVar4;
        Intrinsics.checkNotNullParameter(termContentTextData, "termContentTextData");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-579101816);
        if ((i2 & 6) == 0) {
            i5 = (c0814p.e(j) ? 4 : 2) | i2;
        } else {
            i5 = i2;
        }
        if ((i2 & 48) == 0) {
            i5 |= c0814p.f(termContentTextData) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i5 |= c0814p.f(aVar) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            bool2 = bool;
            i5 |= c0814p.f(bool2) ? 2048 : 1024;
        } else {
            bool2 = bool;
        }
        if ((i2 & 24576) == 0) {
            i5 |= c0814p.f(str) ? 16384 : 8192;
        }
        if ((196608 & i2) == 0) {
            str4 = str2;
            i5 |= c0814p.f(str4) ? 131072 : 65536;
        } else {
            str4 = str2;
        }
        if ((1572864 & i2) == 0) {
            str5 = str3;
            i5 |= c0814p.f(str5) ? 1048576 : 524288;
        } else {
            str5 = str3;
        }
        if ((i2 & 12582912) == 0) {
            i5 |= c0814p.g(z) ? 8388608 : 4194304;
        }
        int i10 = i4 & 256;
        if (i10 != 0) {
            i5 |= 100663296;
            qVar2 = qVar;
        } else {
            qVar2 = qVar;
            if ((i2 & 100663296) == 0) {
                i5 |= c0814p.f(qVar2) ? 67108864 : 33554432;
            }
        }
        if ((i2 & 805306368) == 0) {
            i5 |= c0814p.h(function2) ? 536870912 : 268435456;
        }
        if ((i3 & 6) == 0) {
            i6 = i5;
            i7 = i3 | (c0814p.h(dVar) ? 4 : 2);
        } else {
            i6 = i5;
            i7 = i3;
        }
        if ((i3 & 48) == 0) {
            i7 |= c0814p.h(cVar) ? 32 : 16;
        }
        int i11 = i7;
        if ((i3 & 384) == 0) {
            i11 |= 128;
        }
        if ((i6 & 306783379) == 306783378 && (i11 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            i9 = i;
            qVar4 = qVar2;
        } else {
            c0814p.S();
            if ((i2 & 1) == 0 || c0814p.w()) {
                qVar3 = i10 != 0 ? androidx.compose.ui.n.b : qVar2;
                i8 = AbstractC3205m5.g(c0814p).a;
            } else {
                c0814p.Q();
                i8 = i;
                qVar3 = qVar2;
            }
            c0814p.q();
            com.google.android.gms.internal.mlkit_vision_document_scanner.R4.a(androidx.compose.foundation.layout.K0.c(qVar3, 1.0f), null, 0L, 0L, 0L, null, false, null, null, null, androidx.compose.runtime.internal.e.e(1180129858, new com.quizlet.features.termlist.ui.c(i8, j, termContentTextData, bool2, z, str4, str5, function2, dVar, cVar, aVar, str), c0814p), c0814p, 0, 1022);
            i9 = i8;
            qVar4 = qVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.features.termlist.ui.a
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i2 | 1);
                    int iH2 = C0776c.H(i3);
                    int i12 = i9;
                    int i13 = i4;
                    I3.c(j, termContentTextData, aVar, bool, str, str2, str3, z, qVar4, function2, dVar, cVar, i12, (InterfaceC0806l) obj, iH, iH2, i13);
                    return Unit.a;
                }
            };
        }
    }

    public static void d(int i, int i2) {
        String strB;
        if (i < 0 || i >= i2) {
            if (i < 0) {
                strB = J3.b("%s (%s) must not be negative", "index", Integer.valueOf(i));
            } else {
                if (i2 < 0) {
                    throw new IllegalArgumentException(android.support.v4.media.session.a.f(i2, "negative size: "));
                }
                strB = J3.b("%s (%s) must be less than size (%s)", "index", Integer.valueOf(i), Integer.valueOf(i2));
            }
            throw new IndexOutOfBoundsException(strB);
        }
    }

    public static void e(int i, int i2, int i3) {
        if (i < 0 || i2 < i || i2 > i3) {
            throw new IndexOutOfBoundsException((i < 0 || i > i3) ? f(i, i3, "start index") : (i2 < 0 || i2 > i3) ? f(i2, i3, "end index") : J3.b("end index (%s) must not be less than start index (%s)", Integer.valueOf(i2), Integer.valueOf(i)));
        }
    }

    public static String f(int i, int i2, String str) {
        if (i < 0) {
            return J3.b("%s (%s) must not be negative", str, Integer.valueOf(i));
        }
        if (i2 >= 0) {
            return J3.b("%s (%s) must not be greater than size (%s)", str, Integer.valueOf(i), Integer.valueOf(i2));
        }
        throw new IllegalArgumentException(android.support.v4.media.session.a.f(i2, "negative size: "));
    }
}
