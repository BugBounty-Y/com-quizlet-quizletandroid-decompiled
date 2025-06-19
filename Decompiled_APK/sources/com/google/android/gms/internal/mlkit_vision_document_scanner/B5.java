package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0418x;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.navigation.compose.C1280m;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_document_scanner.B5;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class B5 {
    public static final void a(final androidx.compose.ui.graphics.painter.b thumbnailIcon, final com.quizlet.assembly.compose.listitems.j thumbnailColor, final String title, final String metadata, final androidx.compose.ui.q qVar, final boolean z, final androidx.compose.runtime.internal.d dVar, final boolean z2, com.quizlet.assembly.compose.listitems.z zVar, final Function0 function0, final androidx.compose.ui.text.L l, final int i, final androidx.compose.ui.text.L l2, final float f, final float f2, InterfaceC0806l interfaceC0806l, final int i2, final int i3) {
        int i4;
        androidx.compose.ui.q qVar2;
        int i5;
        int i6;
        com.quizlet.assembly.compose.listitems.z zVar2;
        C0814p c0814p;
        final com.quizlet.assembly.compose.listitems.z zVar3;
        Intrinsics.checkNotNullParameter(thumbnailIcon, "thumbnailIcon");
        Intrinsics.checkNotNullParameter(thumbnailColor, "thumbnailColor");
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1297357526);
        if ((i2 & 6) == 0) {
            i4 = (c0814p2.h(thumbnailIcon) ? 4 : 2) | i2;
        } else {
            i4 = i2;
        }
        if ((i2 & 48) == 0) {
            i4 |= c0814p2.f(thumbnailColor) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i4 |= c0814p2.f(title) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i4 |= c0814p2.f(metadata) ? 2048 : 1024;
        }
        if ((i2 & 24576) == 0) {
            qVar2 = qVar;
            i4 |= c0814p2.f(qVar2) ? 16384 : 8192;
        } else {
            qVar2 = qVar;
        }
        if ((i2 & 196608) == 0) {
            i4 |= c0814p2.g(z) ? 131072 : 65536;
        }
        if ((i2 & 1572864) == 0) {
            i4 |= c0814p2.h(dVar) ? 1048576 : 524288;
        }
        if ((i2 & 12582912) == 0) {
            i4 |= c0814p2.g(z2) ? 8388608 : 4194304;
        }
        if ((i2 & 100663296) == 0) {
            i4 |= 33554432;
        }
        if ((i2 & 805306368) == 0) {
            i4 |= c0814p2.h(function0) ? 536870912 : 268435456;
        }
        if ((i3 & 6) == 0) {
            i5 = i3 | (c0814p2.f(l) ? 4 : 2);
        } else {
            i5 = i3;
        }
        if ((i3 & 48) == 0) {
            i5 |= c0814p2.d(i) ? 32 : 16;
        }
        if ((i3 & 384) == 0) {
            i5 |= c0814p2.f(l2) ? 256 : 128;
        }
        if ((i3 & 3072) == 0) {
            i5 |= c0814p2.c(f) ? 2048 : 1024;
        }
        if ((i3 & 24576) == 0) {
            i5 |= c0814p2.c(f2) ? 16384 : 8192;
        }
        int i7 = i5;
        if ((i4 & 306783379) == 306783378 && (i7 & 9363) == 9362 && c0814p2.x()) {
            c0814p2.Q();
            zVar3 = zVar;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i2 & 1) == 0 || c0814p2.w()) {
                c0814p2.X(-1880547989);
                com.quizlet.themes.b bVar = (com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a);
                float f3 = com.quizlet.assembly.compose.listitems.A.a;
                long jG = bVar.b.g();
                com.quizlet.ui.resources.designsystem.generated.p pVar = bVar.b;
                com.quizlet.assembly.compose.listitems.z zVar4 = new com.quizlet.assembly.compose.listitems.z(jG, pVar.e(), pVar.f(), pVar.f(), jG, pVar.b(), pVar.b(), pVar.b());
                c0814p2.p(false);
                i6 = i4 & (-234881025);
                zVar2 = zVar4;
            } else {
                c0814p2.Q();
                i6 = i4 & (-234881025);
                zVar2 = zVar;
            }
            c0814p2.q();
            int i8 = i6 >> 3;
            c0814p = c0814p2;
            b(androidx.compose.runtime.internal.e.e(-1491459567, new com.quizlet.assembly.compose.listitems.g(thumbnailIcon, thumbnailColor, f, f2), c0814p2), androidx.compose.runtime.internal.e.e(669096978, new com.quizlet.assembly.compose.listitems.h(title, l, i, 0), c0814p2), androidx.compose.runtime.internal.e.e(-1465313773, new androidx.navigation.compose.o(5, metadata, l2), c0814p2), qVar2, z, dVar, z2, zVar2, null, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, function0, c0814p, (i8 & 7168) | 438 | (57344 & i8) | (458752 & i8) | (i8 & 3670016), (i6 >> 24) & ContentType.LONG_FORM_ON_DEMAND, 1792);
            zVar3 = zVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.assembly.compose.listitems.e
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i2 | 1);
                    int iH2 = C0776c.H(i3);
                    float f4 = f;
                    float f5 = f2;
                    B5.a(thumbnailIcon, thumbnailColor, title, metadata, qVar, z, dVar, z2, zVar3, function0, l, i, l2, f4, f5, (InterfaceC0806l) obj, iH, iH2);
                    return Unit.a;
                }
            };
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:105:0x015e  */
    /* JADX WARN: Removed duplicated region for block: B:106:0x0160  */
    /* JADX WARN: Removed duplicated region for block: B:108:0x0164  */
    /* JADX WARN: Removed duplicated region for block: B:111:0x0169  */
    /* JADX WARN: Removed duplicated region for block: B:114:0x0171  */
    /* JADX WARN: Removed duplicated region for block: B:115:0x01b0  */
    /* JADX WARN: Removed duplicated region for block: B:118:0x01e6  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x020c  */
    /* JADX WARN: Removed duplicated region for block: B:126:0x0219  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x021c  */
    /* JADX WARN: Removed duplicated region for block: B:131:0x027d  */
    /* JADX WARN: Removed duplicated region for block: B:133:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:45:0x008e  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x0093  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x00ac  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00c4  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00ce  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x00e4  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x00ef  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x00f4  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x012e  */
    /* JADX WARN: Type inference failed for: r10v10, types: [int] */
    /* JADX WARN: Type inference failed for: r10v17 */
    /* JADX WARN: Type inference failed for: r10v21 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(androidx.compose.runtime.internal.d r40, androidx.compose.runtime.internal.d r41, androidx.compose.runtime.internal.d r42, androidx.compose.ui.q r43, boolean r44, androidx.compose.runtime.internal.d r45, boolean r46, com.quizlet.assembly.compose.listitems.z r47, androidx.compose.foundation.layout.A0 r48, float r49, float r50, kotlin.jvm.functions.Function0 r51, androidx.compose.runtime.InterfaceC0806l r52, int r53, int r54, int r55) {
        /*
            Method dump skipped, instructions count: 664
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.B5.b(androidx.compose.runtime.internal.d, androidx.compose.runtime.internal.d, androidx.compose.runtime.internal.d, androidx.compose.ui.q, boolean, androidx.compose.runtime.internal.d, boolean, com.quizlet.assembly.compose.listitems.z, androidx.compose.foundation.layout.A0, float, float, kotlin.jvm.functions.Function0, androidx.compose.runtime.l, int, int, int):void");
    }

    public static final void c(androidx.compose.ui.graphics.painter.b icon, androidx.compose.ui.n nVar, boolean z, String str, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(icon, "icon");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1742222332);
        if (((i | (c0814p.h(icon) ? 4 : 2) | 48 | (c0814p.g(z) ? 256 : 128) | (c0814p.f(str) ? 2048 : 1024) | (c0814p.h(function0) ? 16384 : 8192)) & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            nVar2 = androidx.compose.ui.n.b;
            d(AbstractC0460p.l(nVar2, z, null, function0, 6), androidx.compose.runtime.internal.e.e(2065703107, new com.quizlet.assembly.compose.listitems.i(icon, str, 0), c0814p), c0814p, 48, 0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.listitems.b(icon, nVar2, z, str, function0, i);
        }
    }

    public static final void d(androidx.compose.ui.q qVar, Function2 action, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        Intrinsics.checkNotNullParameter(action, "action");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1712581302);
        int i4 = i2 & 1;
        if (i4 != 0) {
            i3 = i | 6;
        } else {
            i3 = (c0814p.f(qVar) ? 4 : 2) | i;
        }
        if ((i & 48) == 0) {
            i3 |= c0814p.h(action) ? 32 : 16;
        }
        if ((i3 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            if (i4 != 0) {
                qVar = androidx.compose.ui.n.b;
            }
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.k(qVar, com.quizlet.themes.m.s0), "AssemblyContentListItemActionIcon");
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.e, false);
            int i5 = c0814p.P;
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
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            action.invoke(c0814p, Integer.valueOf((i3 >> 3) & 14));
            c0814p.p(true);
        }
        androidx.compose.ui.q qVar2 = qVar;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.listitems.c(qVar2, action, i, i2, 0);
        }
    }

    public static final void e(String metadata, androidx.compose.ui.n nVar, androidx.compose.ui.text.L l, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        C0814p c0814p;
        androidx.compose.ui.n nVar3;
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1030354386);
        int i2 = i | (c0814p2.f(metadata) ? 4 : 2) | 48 | (c0814p2.f(l) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            nVar3 = nVar;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i & 1) == 0 || c0814p2.w()) {
                nVar2 = androidx.compose.ui.n.b;
            } else {
                c0814p2.Q();
                nVar2 = nVar;
            }
            c0814p2.q();
            c0814p = c0814p2;
            androidx.compose.ui.n nVar4 = nVar2;
            androidx.compose.material3.Q4.b(metadata, nVar4, 0L, 0L, null, 0L, null, 0L, 2, false, 1, 0, null, l, c0814p, i2 & 126, ((i2 << 12) & 3670016) | 3120, 55292);
            nVar3 = nVar4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(i, 5, metadata, nVar3, l);
        }
    }

    public static final void f(final androidx.compose.ui.graphics.painter.b icon, final com.quizlet.assembly.compose.listitems.j color, androidx.compose.ui.q qVar, final float f, final float f2, InterfaceC0806l interfaceC0806l, final int i) {
        androidx.compose.ui.q qVar2;
        long j;
        long j2;
        boolean z;
        final androidx.compose.ui.q qVar3;
        Intrinsics.checkNotNullParameter(icon, "icon");
        Intrinsics.checkNotNullParameter(color, "color");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1653439622);
        int i2 = i | (c0814p.h(icon) ? 4 : 2);
        if ((i & 48) == 0) {
            i2 |= c0814p.f(color) ? 32 : 16;
        }
        int i3 = i2 | 3456 | (c0814p.c(f) ? 16384 : 8192) | (c0814p.c(f2) ? 131072 : 65536);
        if ((74899 & i3) == 74898 && c0814p.x()) {
            c0814p.Q();
            qVar3 = qVar;
        } else {
            c0814p.S();
            int i4 = i & 1;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            if (i4 == 0 || c0814p.w()) {
                qVar2 = nVar;
            } else {
                c0814p.Q();
                qVar2 = qVar;
            }
            c0814p.q();
            androidx.compose.ui.q qVarK = androidx.compose.foundation.layout.K0.k(qVar2, f);
            color.getClass();
            c0814p.X(1772582401);
            int iOrdinal = color.ordinal();
            if (iOrdinal == 0) {
                c0814p.X(-2084629764);
                j = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).A;
                c0814p.p(false);
            } else if (iOrdinal == 1) {
                c0814p.X(-2084626822);
                j = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).C;
                c0814p.p(false);
            } else if (iOrdinal == 2) {
                c0814p.X(-2084623843);
                j = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).E;
                c0814p.p(false);
            } else if (iOrdinal == 3) {
                c0814p.X(-2084620903);
                j = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).G;
                c0814p.p(false);
            } else if (iOrdinal == 4) {
                c0814p.X(-2084618087);
                j = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).I;
                c0814p.p(false);
            } else {
                if (iOrdinal != 5) {
                    throw com.google.android.gms.measurement.internal.Z.j(-2084631092, c0814p, false);
                }
                c0814p.X(-2084615106);
                j = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).K;
                c0814p.p(false);
            }
            c0814p.p(false);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(AbstractC0460p.f(qVarK, j, androidx.compose.ui.graphics.F.a), "AssemblyContentListItemThumbnailIcon");
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i5 = c0814p.P;
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
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.ui.q qVarK2 = androidx.compose.foundation.layout.K0.k(C0418x.a.a(nVar, androidx.compose.ui.b.e), f2);
            c0814p.X(-361841727);
            int iOrdinal2 = color.ordinal();
            if (iOrdinal2 != 0) {
                if (iOrdinal2 == 1) {
                    c0814p.X(-2131543122);
                    j2 = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).D;
                    c0814p.p(false);
                } else if (iOrdinal2 == 2) {
                    c0814p.X(-2131540335);
                    j2 = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).F;
                    c0814p.p(false);
                } else if (iOrdinal2 == 3) {
                    c0814p.X(-2131537587);
                    j2 = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).H;
                    c0814p.p(false);
                } else if (iOrdinal2 == 4) {
                    c0814p.X(-2131534963);
                    j2 = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).J;
                    c0814p.p(false);
                } else {
                    if (iOrdinal2 != 5) {
                        throw com.google.android.gms.measurement.internal.Z.j(-2131547230, c0814p, false);
                    }
                    c0814p.X(-2131532174);
                    j2 = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).L;
                    z = false;
                    c0814p.p(false);
                }
                z = false;
            } else {
                c0814p.X(-2131545872);
                j2 = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).B;
                z = false;
                c0814p.p(false);
            }
            c0814p.p(z);
            androidx.compose.material3.D1.a(icon, null, qVarK2, j2, c0814p, (i3 & 14) | 48, 0);
            c0814p.p(true);
            qVar3 = qVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.assembly.compose.listitems.d
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    float f3 = f;
                    float f4 = f2;
                    B5.f(icon, color, qVar3, f3, f4, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final void g(String title, androidx.compose.ui.n nVar, androidx.compose.ui.text.L l, int i, InterfaceC0806l interfaceC0806l, int i2) {
        androidx.compose.ui.n nVar2;
        C0814p c0814p;
        androidx.compose.ui.n nVar3;
        Intrinsics.checkNotNullParameter(title, "title");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-218771982);
        int i3 = i2 | (c0814p2.f(title) ? 4 : 2) | 48 | (c0814p2.f(l) ? 256 : 128) | (c0814p2.d(i) ? 2048 : 1024);
        if ((i3 & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            nVar3 = nVar;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i2 & 1) == 0 || c0814p2.w()) {
                nVar2 = androidx.compose.ui.n.b;
            } else {
                c0814p2.Q();
                nVar2 = nVar;
            }
            c0814p2.q();
            c0814p = c0814p2;
            androidx.compose.ui.n nVar4 = nVar2;
            androidx.compose.material3.Q4.b(title, nVar4, 0L, 0L, null, 0L, null, 0L, 2, false, i, 0, null, l, c0814p, i3 & 126, (i3 & 7168) | 48 | ((i3 << 12) & 3670016), 55292);
            nVar3 = nVar4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, i2, 2, (androidx.compose.ui.q) nVar3, (Object) title, (Object) l);
        }
    }

    public static final void h(androidx.compose.ui.n nVar, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1015503300);
        int i2 = i | 6 | (c0814p.h(dVar) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.d();
            androidx.compose.ui.q qVarC = androidx.compose.ui.draw.g.c(nVar, androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.g));
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i3 = c0814p.P;
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
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC2, C0914j.d);
            androidx.compose.animation.d0.w((i2 >> 3) & 14, dVar, c0814p, true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1280m(nVar, dVar, i, 4);
        }
    }
}
