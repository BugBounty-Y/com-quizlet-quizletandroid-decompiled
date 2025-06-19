package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
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
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.compose.ui.q;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3423a3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3594c5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3626g5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3745v5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.a3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3423a3 {
    public static final void a(Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1769227534);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(function0) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(androidx.compose.ui.n.b, 1.0f);
            com.quizlet.themes.m.g.s();
            AbstractC3594c5.a((i2 << 3) & ContentType.LONG_FORM_ON_DEMAND, c0814p, AbstractC0382e.y(qVarC, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), function0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.flashcards.screens.b(i, 3, function0);
        }
    }

    public static final void b(Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1072556799);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(function0) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(androidx.compose.ui.n.b, 1.0f);
            com.quizlet.themes.m.g.s();
            AbstractC3626g5.b((i2 << 3) & ContentType.LONG_FORM_ON_DEMAND, c0814p, AbstractC0382e.y(qVarC, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), function0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.flashcards.screens.b(i, 4, function0);
        }
    }

    public static final void c(int i, InterfaceC0806l interfaceC0806l, com.quizlet.qutils.string.g gVar, String str, Function0 function0, Function1 function1, boolean z) {
        boolean z2;
        int i2;
        Function1 function12;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1942115318);
        if ((i & 6) == 0) {
            z2 = z;
            i2 = (c0814p2.g(z2) ? 4 : 2) | i;
        } else {
            z2 = z;
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.h(gVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.f(str) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.h(function0) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            function12 = function1;
            i2 |= c0814p2.h(function12) ? 16384 : 8192;
        } else {
            function12 = function1;
        }
        if ((i2 & 9363) == 9362 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            Object obj = C0804k.a;
            androidx.compose.ui.platform.Q0 q0 = (androidx.compose.ui.platform.Q0) c0814p2.j(AbstractC0955m0.n);
            String strD = AbstractC3106b5.d(c0814p2, R.string.settings_reauth_password_input_hint);
            c0814p2.X(-1875714118);
            String strA = gVar == null ? null : gVar.a((Context) c0814p2.j(AndroidCompositionLocals_androidKt.b));
            c0814p2.p(false);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.s();
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), "PasswordInputTag");
            c0814p2.X(-1875718807);
            boolean zF = ((i2 & 7168) == 2048) | c0814p2.f(q0);
            Object objI = c0814p2.I();
            if (zF || objI == obj) {
                objI = new com.quizlet.assembly.compose.modals.w(q0, function0, 7);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC3745v5.b(str, function12, qVarG, null, strD, 0, 0, null, 7, 7, (Function0) objI, strA, false, null, null, z2, 0, null, DefinitionKt.NO_Float_VALUE, null, null, c0814p, ((i2 >> 6) & 14) | ((i2 >> 9) & ContentType.LONG_FORM_ON_DEMAND), ((i2 << 27) & 1879048192) | 54, 0, 33014760);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.folders.addtofolder.composables.q(z, gVar, str, function0, function1, i, 3);
        }
    }

    public static final void d(final com.quizlet.features.settings.data.states.r uiState, final androidx.compose.ui.q qVar, final com.quizlet.qutils.string.g gVar, final String str, final boolean z, final Function0 function0, final Function0 function02, final Function0 function03, final Function1 function1, InterfaceC0806l interfaceC0806l, final int i) {
        boolean z2;
        int i2;
        int i3;
        Intrinsics.checkNotNullParameter(uiState, "uiState");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(891363723);
        int i4 = i | (c0814p.f(uiState) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16) | (c0814p.h(gVar) ? 256 : 128) | (c0814p.f(str) ? 2048 : 1024) | (c0814p.g(z) ? 16384 : 8192) | (c0814p.h(function0) ? 131072 : 65536) | (c0814p.h(function02) ? 1048576 : 524288) | (c0814p.h(function03) ? 8388608 : 4194304) | (c0814p.h(function1) ? 67108864 : 33554432);
        if ((38347923 & i4) == 38347922 && c0814p.x()) {
            c0814p.Q();
        } else {
            int i5 = i4 >> 3;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i6 = c0814p.P;
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
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i6))) {
                android.support.v4.media.session.a.z(i6, c0814p, i6, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            com.quizlet.features.settings.data.states.o oVar = com.quizlet.features.settings.data.states.o.a;
            boolean zB = Intrinsics.b(uiState, oVar);
            com.quizlet.features.settings.data.states.p pVar = com.quizlet.features.settings.data.states.p.a;
            com.quizlet.features.settings.data.states.q qVar2 = com.quizlet.features.settings.data.states.q.a;
            if (zB) {
                i2 = 1488652692;
                i3 = R.string.re_auth_facebook_description;
                z2 = false;
            } else {
                z2 = false;
                if (Intrinsics.b(uiState, pVar)) {
                    i2 = 1488656338;
                    i3 = R.string.re_auth_google_description;
                } else {
                    if (!Intrinsics.b(uiState, qVar2)) {
                        throw com.google.android.gms.measurement.internal.Z.j(1488650636, c0814p, false);
                    }
                    i2 = 1488659988;
                    i3 = R.string.re_auth_password_description;
                }
            }
            androidx.compose.material3.Q4.b(com.google.android.gms.measurement.internal.Z.h(c0814p, i2, i3, c0814p, z2), null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.b)).o, c0814p, 0, 0, 65530);
            c0814p = c0814p;
            if (Intrinsics.b(uiState, oVar)) {
                c0814p.X(-1095861636);
                a(function03, c0814p, (i4 >> 21) & 14);
                c0814p.p(false);
            } else if (Intrinsics.b(uiState, pVar)) {
                c0814p.X(-1095729824);
                b(function02, c0814p, (i4 >> 18) & 14);
                c0814p.p(false);
            } else {
                if (!Intrinsics.b(uiState, qVar2)) {
                    throw com.google.android.gms.measurement.internal.Z.j(1488668511, c0814p, false);
                }
                c0814p.X(-1095591905);
                int i7 = i4 >> 12;
                c((i5 & 896) | (i7 & 14) | (i5 & ContentType.LONG_FORM_ON_DEMAND) | ((i4 >> 6) & 7168) | (i7 & 57344), c0814p, gVar, str, function0, function1, z);
                c0814p.p(false);
            }
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(qVar, gVar, str, z, function0, function02, function03, function1, i) { // from class: com.quizlet.features.settings.composables.deleteaccount.l
                public final /* synthetic */ q b;
                public final /* synthetic */ com.quizlet.qutils.string.g c;
                public final /* synthetic */ String d;
                public final /* synthetic */ boolean e;
                public final /* synthetic */ Function0 f;
                public final /* synthetic */ Function0 g;
                public final /* synthetic */ Function0 h;
                public final /* synthetic */ Function1 i;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    Function0 function04 = this.h;
                    Function1 function12 = this.i;
                    AbstractC3423a3.d(this.a, this.b, this.c, this.d, this.e, this.f, this.g, function04, function12, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }
}
