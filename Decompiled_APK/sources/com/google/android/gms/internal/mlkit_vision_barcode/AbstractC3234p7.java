package com.google.android.gms.internal.mlkit_vision_barcode;

import android.os.Build;
import android.widget.RemoteViews;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0418x;
import androidx.compose.foundation.layout.FillElement;
import androidx.compose.foundation.layout.HorizontalAlignElement;
import androidx.compose.foundation.pager.C0466e;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3234p7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3578a5;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.quizlet.assembly.compose.buttons.C4076a;
import com.quizlet.data.model.EnumC4175w;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.AbstractC4386e;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.C4390i;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.C4392k;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.C4394m;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.p7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3234p7 {
    public static final void a(String str, String str2, String str3, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1532922103);
        int i2 = i | (c0814p.f(str) ? 4 : 2) | (c0814p.f(str2) ? 32 : 16) | (c0814p.f(str3) ? 256 : 128) | (c0814p.h(function0) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.i iVar = androidx.compose.ui.b.e;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            FillElement fillElement = androidx.compose.foundation.layout.K0.c;
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            androidx.compose.ui.q qVarF = AbstractC0460p.f(fillElement, ((com.quizlet.themes.b) c0814p.j(b)).b.n(), androidx.compose.ui.graphics.F.a);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(iVar, false);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarF);
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
            C0776c.E(c0814p, qVarC, C0914j.d);
            C0418x c0418x = C0418x.a;
            androidx.compose.runtime.B b2 = com.quizlet.themes.w.a;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(b2)).n;
            long jE = ((com.quizlet.themes.b) c0814p.j(b)).b.e();
            androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            androidx.compose.material3.Q4.b(str, AbstractC0382e.u(qVarC2, com.quizlet.ui.resources.designsystem.generated.j.h), jE, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, l, c0814p, i2 & 14, 0, 65016);
            com.quizlet.themes.e.a(c0814p).a.getClass();
            c0814p.X(-280740818);
            androidx.compose.ui.graphics.painter.b bVarA = Z4.a(R.drawable.ic_sys_fullscreen, c0814p, 0);
            c0814p.p(false);
            AbstractC3578a5.a(bVarA, AbstractC3106b5.d(c0814p, R.string.magic_notes_detail_open_flashcards_full_screen_description), c0418x.a(nVar, androidx.compose.ui.b.i), function0, false, C4076a.f, null, 0L, c0814p, i2 & 7168, OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_BACKWARD_COMPATIBILITY);
            String strC = AbstractC3106b5.c(R.string.progress_count, new Object[]{str2, str3}, c0814p);
            androidx.compose.ui.text.L l2 = ((com.quizlet.themes.f) c0814p.j(b2)).l;
            long jF = ((com.quizlet.themes.b) c0814p.j(b)).b.f();
            androidx.compose.ui.q qVarA = c0418x.a(nVar, androidx.compose.ui.b.h);
            mVar.u();
            androidx.compose.material3.Q4.b(strC, AbstractC0382e.y(qVarA, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, 7), jF, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l2, c0814p, 0, 0, 65528);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i((Object) str, (Object) str2, (Object) str3, function0, i, 16);
        }
    }

    public static final void b(androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(2072833871);
        if ((((c0814p.f(qVar) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(qVar, "flashcardsLoading");
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i2 = c0814p.P;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            S5.d(com.quizlet.themes.m.G, androidx.compose.foundation.layout.K0.c(androidx.compose.ui.n.b, 1.0f), null, c0814p, 48);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.d(i, 7, qVar);
        }
    }

    public static final void c(final kotlinx.collections.immutable.b bVar, final EnumC4175w enumC4175w, androidx.compose.ui.q qVar, Function0 function0, Function0 function02, Function0 function03, Function0 function04, Function0 function05, boolean z, boolean z2, boolean z3, Function0 function06, Function0 function07, Function0 function08, InterfaceC0806l interfaceC0806l, final int i, final int i2) {
        int i3;
        androidx.compose.ui.q qVar2;
        int i4;
        int i5;
        Function0 function09;
        int i6;
        Function0 function010;
        int i7;
        Function0 function011;
        int i8;
        Function0 function012;
        int i9;
        boolean z4;
        int i10;
        int i11;
        int i12;
        int i13;
        int i14;
        int i15;
        int i16;
        Function0 function013;
        Function0 function014;
        Function0 function015;
        Function0 function016;
        int i17;
        Function0 function017;
        Function0 function018;
        Function0 function019;
        Function0 function020;
        androidx.compose.ui.q qVar3;
        boolean z5;
        boolean z6;
        Function0 function021;
        Function0 function022;
        Function0 function023;
        Function0 function024;
        boolean z7;
        boolean z8;
        C0814p c0814p;
        final Function0 function025;
        final Function0 function026;
        final boolean z9;
        final boolean z10;
        final Function0 function027;
        final androidx.compose.ui.q qVar4;
        final Function0 function028;
        final Function0 function029;
        final Function0 function030;
        C0814p c0814p2;
        final Function0 function031;
        final Function0 function032;
        final boolean z11;
        C0814p c0814p3 = (C0814p) interfaceC0806l;
        c0814p3.Z(-1499828146);
        if ((i & 6) == 0) {
            i3 = i | (c0814p3.h(bVar) ? 4 : 2);
        } else {
            i3 = i;
        }
        if ((i & 48) == 0) {
            i3 |= c0814p3.f(enumC4175w) ? 32 : 16;
        }
        int i18 = i2 & 4;
        if (i18 != 0) {
            i4 = i3 | 384;
            qVar2 = qVar;
        } else {
            qVar2 = qVar;
            i4 = i3 | (c0814p3.f(qVar2) ? 256 : 128);
        }
        int i19 = i2 & 8;
        if (i19 != 0) {
            i5 = i4 | 3072;
        } else {
            i5 = i4 | (c0814p3.h(function0) ? 2048 : 1024);
        }
        int i20 = i2 & 16;
        if (i20 != 0) {
            i6 = i5 | 24576;
            function09 = function02;
        } else {
            function09 = function02;
            i6 = i5 | (c0814p3.h(function09) ? 16384 : 8192);
        }
        int i21 = i2 & 32;
        if (i21 != 0) {
            i7 = i6 | 196608;
            function010 = function03;
        } else {
            function010 = function03;
            i7 = i6 | (c0814p3.h(function010) ? 131072 : 65536);
        }
        int i22 = i2 & 64;
        if (i22 != 0) {
            i8 = i7 | 1572864;
            function011 = function04;
        } else {
            function011 = function04;
            i8 = i7 | (c0814p3.h(function011) ? 1048576 : 524288);
        }
        int i23 = i2 & 128;
        if (i23 != 0) {
            i9 = i8 | 12582912;
            function012 = function05;
        } else {
            function012 = function05;
            i9 = i8 | (c0814p3.h(function012) ? 8388608 : 4194304);
        }
        int i24 = i2 & 256;
        if (i24 != 0) {
            i10 = i9 | 100663296;
            z4 = z;
        } else {
            z4 = z;
            i10 = i9 | (c0814p3.g(z4) ? 67108864 : 33554432);
        }
        int i25 = i10;
        int i26 = i2 & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH;
        if (i26 != 0) {
            i12 = i25 | 805306368;
            i11 = i26;
        } else {
            i11 = i26;
            i12 = i25 | (c0814p3.g(z2) ? 536870912 : 268435456);
        }
        int i27 = i2 & 1024;
        int i28 = i27 != 0 ? 6 : c0814p3.g(z3) ? 4 : 2;
        int i29 = i2 & 2048;
        if (i29 != 0) {
            i14 = i28 | 48;
            i13 = i29;
        } else {
            i13 = i29;
            i14 = i28 | (c0814p3.h(function06) ? 32 : 16);
        }
        int i30 = i14;
        int i31 = i2 & 4096;
        if (i31 != 0) {
            i15 = i30 | 384;
        } else {
            i15 = i30 | (c0814p3.h(function07) ? 256 : 128);
        }
        int i32 = i2 & 8192;
        if (i32 != 0) {
            i16 = i15 | 3072;
        } else {
            i16 = i15 | (c0814p3.h(function08) ? 2048 : 1024);
        }
        if ((i12 & 306783379) == 306783378 && (i16 & 1171) == 1170 && c0814p3.x()) {
            c0814p3.Q();
            function028 = function0;
            function025 = function06;
            function026 = function08;
            z10 = z4;
            function027 = function09;
            function032 = function010;
            function029 = function011;
            qVar4 = qVar2;
            c0814p2 = c0814p3;
            function030 = function012;
            z9 = z2;
            z11 = z3;
            function031 = function07;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVar5 = i18 != 0 ? nVar : qVar2;
            Object obj = C0804k.a;
            if (i19 != 0) {
                c0814p3.X(-1408484857);
                Object objI = c0814p3.I();
                if (objI == obj) {
                    objI = new com.quizlet.features.emailconfirmation.ui.composables.c(27);
                    c0814p3.i0(objI);
                }
                function013 = (Function0) objI;
                c0814p3.p(false);
            } else {
                function013 = function0;
            }
            if (i20 != 0) {
                c0814p3.X(-1408483417);
                Object objI2 = c0814p3.I();
                if (objI2 == obj) {
                    objI2 = new com.quizlet.features.emailconfirmation.ui.composables.c(28);
                    c0814p3.i0(objI2);
                }
                function09 = (Function0) objI2;
                c0814p3.p(false);
            }
            if (i21 != 0) {
                c0814p3.X(-1408481977);
                Object objI3 = c0814p3.I();
                if (objI3 == obj) {
                    objI3 = new com.quizlet.features.emailconfirmation.ui.composables.c(29);
                    c0814p3.i0(objI3);
                }
                function010 = (Function0) objI3;
                c0814p3.p(false);
            }
            if (i22 != 0) {
                c0814p3.X(-1408480665);
                Object objI4 = c0814p3.I();
                if (objI4 == obj) {
                    objI4 = new C4392k(0);
                    c0814p3.i0(objI4);
                }
                function011 = (Function0) objI4;
                c0814p3.p(false);
            }
            if (i23 != 0) {
                c0814p3.X(-1408479321);
                Object objI5 = c0814p3.I();
                if (objI5 == obj) {
                    objI5 = new C4392k(1);
                    c0814p3.i0(objI5);
                }
                function014 = (Function0) objI5;
                c0814p3.p(false);
            } else {
                function014 = function012;
            }
            boolean z12 = i24 != 0 ? true : z4;
            boolean z13 = i11 != 0 ? false : z2;
            boolean z14 = i27 != 0 ? false : z3;
            if (i13 != 0) {
                c0814p3.X(-1408473337);
                Object objI6 = c0814p3.I();
                if (objI6 == obj) {
                    objI6 = new C4392k(2);
                    c0814p3.i0(objI6);
                }
                c0814p3.p(false);
                function015 = (Function0) objI6;
            } else {
                function015 = function06;
            }
            if (i31 != 0) {
                c0814p3.X(-1408471961);
                Object objI7 = c0814p3.I();
                if (objI7 == obj) {
                    objI7 = new C4392k(3);
                    c0814p3.i0(objI7);
                }
                c0814p3.p(false);
                function016 = (Function0) objI7;
            } else {
                function016 = function07;
            }
            if (i32 != 0) {
                c0814p3.X(-1408470617);
                Object objI8 = c0814p3.I();
                if (objI8 == obj) {
                    objI8 = new C4392k(4);
                    c0814p3.i0(objI8);
                }
                i17 = 0;
                c0814p3.p(false);
                function017 = (Function0) objI8;
            } else {
                i17 = 0;
                function017 = function08;
            }
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p3, i17);
            int i33 = c0814p3.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p3.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p3, qVar5);
            InterfaceC0915k.D0.getClass();
            int i34 = i16;
            Function0 function033 = C0914j.b;
            c0814p3.b0();
            androidx.compose.ui.q qVar6 = qVar5;
            if (c0814p3.O) {
                c0814p3.k(function033);
            } else {
                c0814p3.l0();
            }
            C0776c.E(c0814p3, bA, C0914j.f);
            C0776c.E(c0814p3, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p3.O || !Intrinsics.b(c0814p3.I(), Integer.valueOf(i33))) {
                android.support.v4.media.session.a.z(i33, c0814p3, i33, c0912h);
            }
            C0776c.E(c0814p3, qVarC, C0914j.d);
            String strD = AbstractC3106b5.d(c0814p3, R.string.magic_notes_flashcards);
            androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.ui.q qVarW = AbstractC0382e.w(qVarC2, f, DefinitionKt.NO_Float_VALUE, 2);
            c0814p3.X(-729366035);
            String strD2 = (!z12 || bVar == null || bVar.isEmpty() || enumC4175w != EnumC4175w.COMPLETE) ? null : AbstractC3106b5.d(c0814p3, R.string.magic_notes_detail_edit_set);
            c0814p3.p(false);
            Function0 function034 = function09;
            AbstractC3189k7.b(strD, qVarW, strD2, function034, c0814p3, (i12 >> 3) & 7168, 0);
            Object[] objArr = new Object[0];
            c0814p3.X(-729355811);
            Object objI9 = c0814p3.I();
            if (objI9 == obj) {
                objI9 = new com.quizlet.features.emailconfirmation.ui.composables.c(26);
                c0814p3.i0(objI9);
            }
            c0814p3.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) L4.d(objArr, null, (Function0) objI9, c0814p3, 3072, 6);
            if (bVar == null || bVar.isEmpty()) {
                Function0 function035 = function010;
                function018 = function011;
                function019 = function013;
                function020 = function014;
                qVar3 = qVar6;
                z5 = z13;
                z6 = z14;
                function021 = function015;
                function022 = function016;
                function023 = function017;
                c0814p3.X(-1135083578);
                if (enumC4175w == EnumC4175w.PENDING) {
                    c0814p3.X(-1135037016);
                    androidx.compose.animation.E.f(((Boolean) interfaceC0773a0.getValue()).booleanValue(), null, null, null, null, AbstractC4386e.a, c0814p3, 1572870, 30);
                    z7 = true;
                    function024 = function035;
                    androidx.compose.animation.E.f(!((Boolean) interfaceC0773a0.getValue()).booleanValue(), null, null, null, null, androidx.compose.runtime.internal.e.e(-636066103, new com.quizlet.assembly.compose.input.g(interfaceC0773a0, function024, 2), c0814p3), c0814p3, 1572870, 30);
                    c0814p3.p(false);
                    z8 = false;
                } else {
                    function024 = function035;
                    z7 = true;
                    c0814p3.X(-1133892248);
                    mVar.s();
                    mVar.s();
                    mVar.p();
                    z8 = false;
                    AbstractC3180j7.a(0, 0, c0814p3, AbstractC0382e.y(nVar, f, DefinitionKt.NO_Float_VALUE, f, com.quizlet.ui.resources.designsystem.generated.j.j, 2));
                    c0814p3.p(false);
                }
                c0814p3.p(z8);
                c0814p = c0814p3;
            } else {
                c0814p3.X(-1133401859);
                c0814p3.X(-729301102);
                boolean zH = c0814p3.h(bVar);
                Object objI10 = c0814p3.I();
                if (zH || objI10 == obj) {
                    objI10 = new C4390i(bVar, 0);
                    c0814p3.i0(objI10);
                }
                c0814p3.p(false);
                C0466e c0466eB = androidx.compose.foundation.pager.I.b(0, (Function0) objI10, c0814p3, 0, 3);
                c0814p3.X(-729298018);
                boolean zF = c0814p3.f(c0466eB) | ((i12 & 3670016) == 1048576);
                Object objI11 = c0814p3.I();
                if (zF || objI11 == obj) {
                    objI11 = new C4394m(c0466eB, function011, null);
                    c0814p3.i0(objI11);
                }
                c0814p3.p(false);
                C0776c.g(c0466eB, function011, (Function2) objI11, c0814p3);
                c0814p3.X(-729286946);
                Object objI12 = c0814p3.I();
                Object obj2 = objI12;
                if (objI12 == obj) {
                    androidx.compose.runtime.snapshots.q qVar7 = new androidx.compose.runtime.snapshots.q();
                    ArrayList arrayList = new ArrayList(kotlin.collections.C.q(bVar, 10));
                    Iterator<E> it2 = bVar.iterator();
                    while (it2.hasNext()) {
                        arrayList.add(com.quizlet.assembly.compose.components.flashcards.a.d);
                    }
                    qVar7.addAll(arrayList);
                    c0814p3.i0(qVar7);
                    obj2 = qVar7;
                }
                c0814p3.p(false);
                com.quizlet.themes.m mVar2 = com.quizlet.themes.m.g;
                mVar2.s();
                float f2 = com.quizlet.ui.resources.designsystem.generated.j.h;
                androidx.compose.foundation.layout.A0 a0C = AbstractC0382e.c(f2, DefinitionKt.NO_Float_VALUE, 2);
                mVar2.u();
                float f3 = com.quizlet.ui.resources.designsystem.generated.j.g;
                function020 = function014;
                qVar3 = qVar6;
                function018 = function011;
                function019 = function013;
                AbstractC3191l0.a(f3, 0, 0, 8154, null, null, a0C, null, c0466eB, null, c0814p3, androidx.compose.runtime.internal.e.e(-1811310070, new com.quizlet.features.notes.detail.composables.magicnotesdetail.p((androidx.compose.runtime.snapshots.q) obj2, function014, bVar, function013), c0814p3), null, null, false);
                int size = bVar.size();
                float f4 = com.quizlet.themes.m.H;
                HorizontalAlignElement horizontalAlignElement = new HorizontalAlignElement(androidx.compose.ui.b.n);
                mVar2.u();
                AbstractC3258s5.a(c0466eB, size, androidx.compose.ui.platform.N.G(AbstractC0382e.y(horizontalAlignElement, DefinitionKt.NO_Float_VALUE, f3, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), "indicator"), 0, f4, DefinitionKt.NO_Float_VALUE, null, 0L, 0L, 0L, 0L, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, c0814p3, 0, 0, 16360);
                String strD3 = AbstractC3106b5.d(c0814p3, R.string.magic_notes_detail_other_ways);
                androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p3.j(com.quizlet.themes.w.a)).k;
                long jF = ((com.quizlet.themes.b) c0814p3.j(com.quizlet.themes.g.a)).b.f();
                mVar2.s();
                mVar2.s();
                androidx.compose.material3.Q4.b(strD3, AbstractC0382e.v(nVar, f2, f2), jF, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p3, 0, 0, 65528);
                C0814p c0814p4 = c0814p3;
                String strD4 = AbstractC3106b5.d(c0814p4, R.string.magic_notes_detail_learn);
                androidx.compose.ui.graphics.painter.b bVarF = com.quizlet.themes.e.a(c0814p4).b.f(c0814p4);
                mVar2.s();
                mVar2.s();
                mVar2.u();
                int i35 = i34 << 9;
                boolean z15 = z13;
                Function0 function036 = function015;
                d(strD4, bVarF, AbstractC0382e.y(nVar, f2, DefinitionKt.NO_Float_VALUE, f2, f3, 2), z15, function036, c0814p4, ((i12 >> 18) & 7168) | (i35 & 57344), 0);
                z5 = z15;
                function021 = function036;
                String strD5 = AbstractC3106b5.d(c0814p4, R.string.magic_notes_detail_test);
                androidx.compose.ui.graphics.painter.b bVarE = com.quizlet.themes.e.a(c0814p4).b.e(c0814p4);
                mVar2.s();
                mVar2.s();
                mVar2.u();
                boolean z16 = z14;
                Function0 function037 = function017;
                d(strD5, bVarE, AbstractC0382e.y(nVar, f2, DefinitionKt.NO_Float_VALUE, f2, f3, 2), z16, function037, c0814p4, (i35 & 7168) | ((i34 << 3) & 57344), 0);
                z6 = z16;
                function023 = function037;
                String strD6 = AbstractC3106b5.d(c0814p4, R.string.magic_notes_detail_match);
                androidx.compose.ui.graphics.painter.b bVarG = com.quizlet.themes.e.a(c0814p4).b.g(c0814p4);
                mVar2.s();
                mVar2.s();
                mVar2.u();
                Function0 function038 = function016;
                d(strD6, bVarG, AbstractC0382e.y(nVar, f2, DefinitionKt.NO_Float_VALUE, f2, f3, 2), false, function038, c0814p4, 57344 & (i34 << 6), 8);
                function022 = function038;
                c0814p4.p(false);
                function024 = function010;
                z7 = true;
                c0814p = c0814p4;
            }
            c0814p.p(z7);
            function025 = function021;
            function026 = function023;
            z9 = z5;
            z10 = z12;
            function027 = function034;
            qVar4 = qVar3;
            function028 = function019;
            function029 = function018;
            function030 = function020;
            c0814p2 = c0814p;
            function031 = function022;
            function032 = function024;
            z11 = z6;
        }
        C0813o0 c0813o0R = c0814p2.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.features.notes.detail.composables.magicnotesdetail.j
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj3, Object obj4) {
                    ((Integer) obj4).getClass();
                    int iH = C0776c.H(i | 1);
                    Function0 function039 = function026;
                    int i36 = i2;
                    AbstractC3234p7.c(bVar, enumC4175w, qVar4, function028, function027, function032, function029, function030, z10, z9, z11, function025, function031, function039, (InterfaceC0806l) obj3, iH, i36);
                    return Unit.a;
                }
            };
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x0063  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x0083  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0085  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0087  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00c7  */
    /* JADX WARN: Removed duplicated region for block: B:56:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void d(java.lang.String r24, androidx.compose.ui.graphics.painter.b r25, androidx.compose.ui.q r26, boolean r27, kotlin.jvm.functions.Function0 r28, androidx.compose.runtime.InterfaceC0806l r29, int r30, int r31) {
        /*
            Method dump skipped, instructions count: 211
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3234p7.d(java.lang.String, androidx.compose.ui.graphics.painter.b, androidx.compose.ui.q, boolean, kotlin.jvm.functions.Function0, androidx.compose.runtime.l, int, int):void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:109:0x0236  */
    /* JADX WARN: Removed duplicated region for block: B:130:0x0289  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x0166  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x01a3  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x01ba  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:89:0x018c -> B:138:0x019d). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void e(androidx.glance.appwidget.N0 r22, android.widget.RemoteViews r23, androidx.glance.p r24, androidx.glance.appwidget.C1179k0 r25) {
        /*
            Method dump skipped, instructions count: 675
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3234p7.e(androidx.glance.appwidget.N0, android.widget.RemoteViews, androidx.glance.p, androidx.glance.appwidget.k0):void");
    }

    public static final void f(RemoteViews remoteViews, androidx.glance.layout.m mVar, int i) {
        androidx.glance.unit.g gVar = mVar.a;
        int i2 = Build.VERSION.SDK_INT;
        androidx.glance.unit.d dVar = androidx.glance.unit.d.a;
        androidx.glance.unit.f fVar = androidx.glance.unit.f.a;
        if (i2 >= 31) {
            if (i2 >= 33 || !kotlin.collections.B.j(fVar, dVar).contains(gVar)) {
                androidx.glance.appwidget.r.a.b(remoteViews, i, gVar);
                return;
            }
            return;
        }
        List listJ = kotlin.collections.B.j(fVar, androidx.glance.unit.e.a, dVar);
        Object obj = androidx.glance.appwidget.r0.a;
        if (listJ.contains(gVar)) {
            return;
        }
        throw new IllegalArgumentException("Using a height of " + gVar + " requires a complex layout before API 31");
    }

    public static final void g(RemoteViews remoteViews, androidx.glance.layout.t tVar, int i) {
        androidx.glance.unit.g gVar = tVar.a;
        int i2 = Build.VERSION.SDK_INT;
        androidx.glance.unit.d dVar = androidx.glance.unit.d.a;
        androidx.glance.unit.f fVar = androidx.glance.unit.f.a;
        if (i2 >= 31) {
            if (i2 >= 33 || !kotlin.collections.B.j(fVar, dVar).contains(gVar)) {
                androidx.glance.appwidget.r.a.c(remoteViews, i, gVar);
                return;
            }
            return;
        }
        List listJ = kotlin.collections.B.j(fVar, androidx.glance.unit.e.a, dVar);
        Object obj = androidx.glance.appwidget.r0.a;
        if (listJ.contains(gVar)) {
            return;
        }
        throw new IllegalArgumentException("Using a width of " + gVar + " requires a complex layout before API 31");
    }

    /* JADX WARN: Code restructure failed: missing block: B:34:0x009d, code lost:
    
        if (r1.e(r4, r13) == r2) goto L60;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:29:0x007f  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00da  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00f7  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0015  */
    /* JADX WARN: Type inference failed for: r3v0, types: [int] */
    /* JADX WARN: Type inference failed for: r3v10, types: [io.ktor.utils.io.t] */
    /* JADX WARN: Type inference failed for: r3v16 */
    /* JADX WARN: Type inference failed for: r3v2, types: [io.ktor.utils.io.t] */
    /* JADX WARN: Type inference failed for: r3v4 */
    /* JADX WARN: Type inference failed for: r3v7 */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:44:0x00da -> B:45:0x00de). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object h(io.ktor.utils.io.n r17, io.ktor.utils.io.t r18, long r19, kotlin.coroutines.jvm.internal.c r21) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 281
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3234p7.h(io.ktor.utils.io.n, io.ktor.utils.io.t, long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final boolean i(androidx.glance.unit.g gVar) {
        boolean z = true;
        if (gVar instanceof androidx.glance.unit.c) {
            return true;
        }
        if (!(Intrinsics.b(gVar, androidx.glance.unit.d.a) ? true : Intrinsics.b(gVar, androidx.glance.unit.e.a) ? true : Intrinsics.b(gVar, androidx.glance.unit.f.a)) && gVar != null) {
            z = false;
        }
        if (z) {
            return false;
        }
        throw new NoWhenBranchMatchedException();
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object j(io.ktor.utils.io.n r4, kotlin.coroutines.jvm.internal.c r5) throws java.lang.Throwable {
        /*
            boolean r0 = r5 instanceof io.ktor.utils.io.p
            if (r0 == 0) goto L13
            r0 = r5
            io.ktor.utils.io.p r0 = (io.ktor.utils.io.p) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            io.ktor.utils.io.p r0 = new io.ktor.utils.io.p
            r0.<init>(r5)
        L18:
            java.lang.Object r5 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            kotlinx.io.a r4 = r0.k
            io.ktor.utils.io.n r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r5 = r4
            r4 = r2
            goto L3d
        L2d:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            kotlinx.io.a r5 = new kotlinx.io.a
            r5.<init>()
        L3d:
            boolean r2 = r4.f()
            if (r2 != 0) goto L57
            kotlinx.io.i r2 = r4.d()
            r5.f(r2)
            r0.j = r4
            r0.k = r5
            r0.m = r3
            java.lang.Object r2 = r4.e(r3, r0)
            if (r2 != r1) goto L3d
            return r1
        L57:
            java.lang.Throwable r4 = r4.c()
            if (r4 != 0) goto L5e
            return r5
        L5e:
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3234p7.j(io.ktor.utils.io.n, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x0047  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x006a  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x009b A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:33:0x009c  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:18:0x004f -> B:24:0x0064). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:22:0x0060 -> B:23:0x0062). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object k(io.ktor.utils.io.n r11, int r12, kotlin.coroutines.jvm.internal.c r13) throws java.io.EOFException {
        /*
            boolean r0 = r13 instanceof io.ktor.utils.io.q
            if (r0 == 0) goto L13
            r0 = r13
            io.ktor.utils.io.q r0 = (io.ktor.utils.io.q) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            io.ktor.utils.io.q r0 = new io.ktor.utils.io.q
            r0.<init>(r13)
        L18:
            java.lang.Object r13 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            int r11 = r0.l
            kotlinx.io.a r12 = r0.k
            io.ktor.utils.io.n r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L62
        L2d:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r12)
            throw r11
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            kotlinx.io.a r13 = new kotlinx.io.a
            r13.<init>()
            r10 = r13
            r13 = r12
            r12 = r10
        L40:
            long r4 = r12.c
            long r6 = (long) r13
            int r2 = (r4 > r6 ? 1 : (r4 == r6 ? 0 : -1))
            if (r2 >= 0) goto L94
            kotlinx.io.i r2 = r11.d()
            boolean r2 = r2.u()
            if (r2 == 0) goto L64
            r0.j = r11
            r0.k = r12
            r0.l = r13
            r0.n = r3
            java.lang.Object r2 = r11.e(r3, r0)
            if (r2 != r1) goto L60
            return r1
        L60:
            r2 = r11
            r11 = r13
        L62:
            r13 = r11
            r11 = r2
        L64:
            boolean r2 = r11.f()
            if (r2 != 0) goto L94
            kotlinx.io.i r2 = r11.d()
            long r4 = com.google.android.gms.internal.mlkit_vision_barcode.u7.c(r2)
            long r6 = (long) r13
            long r8 = r12.c
            long r8 = r6 - r8
            int r2 = (r4 > r8 ? 1 : (r4 == r8 ? 0 : -1))
            if (r2 <= 0) goto L86
            kotlinx.io.i r2 = r11.d()
            long r4 = r12.c
            long r6 = r6 - r4
            r2.n(r12, r6)
            goto L40
        L86:
            kotlinx.io.i r2 = r11.d()
            long r4 = r2.G(r12)
            java.lang.Long r2 = new java.lang.Long
            r2.<init>(r4)
            goto L40
        L94:
            long r0 = r12.c
            long r2 = (long) r13
            int r11 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r11 < 0) goto L9c
            return r12
        L9c:
            java.io.EOFException r11 = new java.io.EOFException
            java.lang.String r0 = "Not enough data available, required "
            java.lang.String r1 = " bytes but only "
            java.lang.StringBuilder r13 = android.support.v4.media.session.a.v(r13, r0, r1)
            long r0 = r12.c
            java.lang.String r12 = " available"
            java.lang.String r12 = android.support.v4.media.session.a.g(r0, r12, r13)
            r11.<init>(r12)
            throw r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3234p7.k(io.ktor.utils.io.n, int, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object l(io.ktor.utils.io.n r4, kotlin.coroutines.jvm.internal.c r5) {
        /*
            boolean r0 = r5 instanceof io.ktor.utils.io.r
            if (r0 == 0) goto L13
            r0 = r5
            io.ktor.utils.io.r r0 = (io.ktor.utils.io.r) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            io.ktor.utils.io.r r0 = new io.ktor.utils.io.r
            r0.<init>(r5)
        L18:
            java.lang.Object r5 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            kotlinx.io.a r4 = r0.k
            io.ktor.utils.io.n r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r5 = r4
            r4 = r2
            goto L3d
        L2d:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            kotlinx.io.a r5 = new kotlinx.io.a
            r5.<init>()
        L3d:
            boolean r2 = r4.f()
            if (r2 != 0) goto L57
            kotlinx.io.i r2 = r4.d()
            r5.f(r2)
            r0.j = r4
            r0.k = r5
            r0.m = r3
            java.lang.Object r2 = r4.e(r3, r0)
            if (r2 != r1) goto L3d
            return r1
        L57:
            java.lang.String r0 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r0)
            java.lang.Throwable r4 = r4.c()
            if (r4 != 0) goto L66
            r5.getClass()
            return r5
        L66:
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3234p7.l(io.ktor.utils.io.n, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r4v2, types: [byte[], java.io.Serializable] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.io.Serializable m(io.ktor.utils.io.n r4, kotlin.coroutines.jvm.internal.c r5) throws java.lang.Throwable {
        /*
            boolean r0 = r5 instanceof io.ktor.utils.io.s
            if (r0 == 0) goto L13
            r0 = r5
            io.ktor.utils.io.s r0 = (io.ktor.utils.io.s) r0
            int r1 = r0.k
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.k = r1
            goto L18
        L13:
            io.ktor.utils.io.s r0 = new io.ktor.utils.io.s
            r0.<init>(r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.k
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L3b
        L27:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r0.k = r3
            java.lang.Object r5 = j(r4, r0)
            if (r5 != r1) goto L3b
            return r1
        L3b:
            kotlinx.io.a r5 = (kotlinx.io.a) r5
            long r0 = r5.c
            int r4 = (int) r0
            java.lang.String r0 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r0)
            byte[] r4 = kotlinx.io.j.d(r5, r4)
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3234p7.m(io.ktor.utils.io.n, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }
}
