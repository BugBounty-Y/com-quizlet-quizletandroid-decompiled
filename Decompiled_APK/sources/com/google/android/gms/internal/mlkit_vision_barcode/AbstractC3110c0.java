package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import android.content.Intent;
import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
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
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3110c0;
import com.quizlet.assembly.compose.buttons.C4093s;
import com.quizlet.features.flashcards.FlashcardsActivity;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Set;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.c0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3110c0 {
    public static final void a(final String primaryText, final boolean z, final androidx.compose.ui.q qVar, boolean z2, final Function0 function0, Function0 function02, int i, InterfaceC0806l interfaceC0806l, final int i2, final int i3) {
        boolean z3;
        int i4;
        Function0 function03;
        int i5;
        int i6;
        int i7;
        final Function0 function04;
        final boolean z4;
        final int i8;
        Intrinsics.checkNotNullParameter(primaryText, "primaryText");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1147066546);
        int i9 = i2 | (c0814p.f(primaryText) ? 4 : 2);
        if ((i2 & 48) == 0) {
            i9 |= c0814p.g(z) ? 32 : 16;
        }
        int i10 = i9 | (c0814p.f(qVar) ? 256 : 128);
        int i11 = i3 & 8;
        if (i11 != 0) {
            i4 = i10 | 3072;
            z3 = z2;
        } else {
            z3 = z2;
            i4 = i10 | (c0814p.g(z3) ? 2048 : 1024);
        }
        int i12 = i4 | (c0814p.h(function0) ? 16384 : 8192);
        int i13 = i3 & 32;
        if (i13 != 0) {
            i5 = i12 | 196608;
            function03 = function02;
        } else {
            function03 = function02;
            i5 = i12 | (c0814p.h(function03) ? 131072 : 65536);
        }
        int i14 = i5 | 524288;
        if ((599187 & i14) == 599186 && c0814p.x()) {
            c0814p.Q();
            i8 = i;
            z4 = z3;
            function04 = function03;
        } else {
            c0814p.S();
            if ((i2 & 1) == 0 || c0814p.w()) {
                if (i11 != 0) {
                    z3 = false;
                }
                androidx.compose.runtime.V v = C0804k.a;
                if (i13 != 0) {
                    c0814p.X(-985307684);
                    Object objI = c0814p.I();
                    if (objI == v) {
                        objI = new com.quizlet.quizletandroid.ui.startpage.nav2.composables.b(9);
                        c0814p.i0(objI);
                    }
                    c0814p.p(false);
                    function03 = (Function0) objI;
                }
                i6 = AbstractC3205m5.g(c0814p).a;
                i7 = i14 & (-3670017);
            } else {
                c0814p.Q();
                i6 = i;
                i7 = i14 & (-3670017);
            }
            boolean z5 = z3;
            Function0 function05 = function03;
            c0814p.q();
            Set set = androidx.compose.material3.windowsizeclass.c.b;
            C4093s c4093s = C4093s.a;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            if (i6 == 0) {
                c0814p.X(-479598893);
                androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(qVar, 1.0f);
                androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
                int i15 = c0814p.P;
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
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i15))) {
                    android.support.v4.media.session.a.z(i15, c0814p, i15, c0912h);
                }
                C0776c.E(c0814p, qVarC2, C0914j.d);
                com.google.android.gms.internal.mlkit_vision_document_scanner.W4.a(primaryText, androidx.compose.foundation.layout.K0.c(nVar, 1.0f), function0, z, null, c4093s, null, null, null, false, c0814p, (i7 & 14) | 48 | ((i7 >> 6) & 896) | ((i7 << 6) & 7168), 976);
                c0814p.X(-1253046550);
                if (z5) {
                    androidx.compose.ui.q qVarC3 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
                    com.quizlet.themes.m.g.s();
                    com.google.android.gms.internal.mlkit_vision_document_scanner.Y4.b(AbstractC3106b5.d(c0814p, R.string.go_back_button), AbstractC0382e.y(qVarC3, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), function05, false, null, null, 0L, 0L, c4093s, null, null, c0814p, (i7 >> 9) & 896, 0, 3576);
                }
                androidx.compose.ui.node.B.s(c0814p, false, true, false);
            } else {
                c0814p.X(-478748036);
                androidx.compose.ui.q qVarC4 = androidx.compose.foundation.layout.K0.c(qVar, 1.0f);
                androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.b, androidx.compose.ui.b.j, c0814p, 6);
                int i16 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
                androidx.compose.ui.q qVarC5 = androidx.compose.ui.a.c(c0814p, qVarC4);
                InterfaceC0915k.D0.getClass();
                C0913i c0913i2 = C0914j.b;
                c0814p.b0();
                if (c0814p.O) {
                    c0814p.k(c0913i2);
                } else {
                    c0814p.l0();
                }
                C0776c.E(c0814p, g0B, C0914j.f);
                C0776c.E(c0814p, interfaceC0803j0L2, C0914j.e);
                C0912h c0912h2 = C0914j.g;
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i16))) {
                    android.support.v4.media.session.a.z(i16, c0814p, i16, c0912h2);
                }
                C0776c.E(c0814p, qVarC5, C0914j.d);
                c0814p.X(-1253027549);
                if (z5) {
                    com.quizlet.themes.m.g.u();
                    com.google.android.gms.internal.mlkit_vision_document_scanner.Y4.b(AbstractC3106b5.d(c0814p, R.string.go_back_button), AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, 11), function05, false, null, null, 0L, 0L, c4093s, null, null, c0814p, (i7 >> 9) & 896, 0, 3576);
                }
                c0814p.p(false);
                com.google.android.gms.internal.mlkit_vision_document_scanner.W4.a(primaryText, nVar, function0, z, null, c4093s, null, null, null, false, c0814p, (i7 & 14) | 48 | ((i7 >> 6) & 896) | ((i7 << 6) & 7168), 976);
                c0814p.p(true);
                c0814p.p(false);
            }
            function04 = function05;
            z4 = z5;
            i8 = i6;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.report.ui.a
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i2 | 1);
                    int i17 = i8;
                    AbstractC3110c0.a(primaryText, z, qVar, z4, function0, function04, i17, (InterfaceC0806l) obj, iH, i3);
                    return Unit.a;
                }
            };
        }
    }

    public static final float b(androidx.compose.foundation.pager.E e) {
        return e.k().e == EnumC0320d0.b ? androidx.compose.ui.geometry.b.d(e.o()) : androidx.compose.ui.geometry.b.e(e.o());
    }

    public static Intent c(Context context, com.quizlet.features.infra.basestudy.data.models.r state) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(state, "state");
        Intent intent = new Intent(context, (Class<?>) FlashcardsActivity.class);
        int i = state.a;
        String str = FlashcardsActivity.j;
        int iA = com.quizlet.generated.enums.A1.FLASHCARDS.a();
        Integer numValueOf = Integer.valueOf(i);
        Long lValueOf = Long.valueOf(state.c);
        AbstractC3266t5.c(intent, numValueOf, state.b, lValueOf, state.e, str, iA, null, state.d, 640);
        return intent;
    }

    public static final boolean d(androidx.compose.foundation.pager.E e) {
        e.k().getClass();
        b(e);
        return b(e) <= DefinitionKt.NO_Float_VALUE;
    }
}
