package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.text.AbstractC0484d0;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
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
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.U5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Map;
import kotlin.Pair;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes2.dex */
public abstract class Y1 {
    public static final void a(androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1963188244);
        if ((i & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            androidx.compose.ui.q qVarW = AbstractC0382e.w(qVar, com.quizlet.ui.resources.designsystem.generated.j.i, DefinitionKt.NO_Float_VALUE, 2);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarW);
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
            String strD = AbstractC3106b5.d(c0814p, R.string.practice_test_detail_disclaimer_title);
            androidx.compose.runtime.B b = com.quizlet.themes.w.a;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(b)).e;
            ((com.quizlet.themes.f) c0814p.j(b)).b.getClass();
            long j = com.quizlet.ui.resources.designsystem.generated.l.s;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            mVar.s();
            Q4.b(strD, AbstractC0382e.w(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, 1), 0L, 0L, null, 0L, null, j, 0, false, 0, 0, null, l, c0814p, 0, 0, 64508);
            String strD2 = AbstractC3106b5.d(c0814p, R.string.practice_test_detail_disclaimer_description);
            int iM = StringsKt.M(strD2, "%1$s", 0, false, 6);
            CharSequence charSequenceSubSequence = strD2.subSequence(0, iM);
            CharSequence charSequenceSubSequence2 = strD2.subSequence(iM + 4, strD2.length());
            C0984d c0984d = new C0984d();
            c0984d.e(charSequenceSubSequence);
            AbstractC0484d0.p(c0984d, "iconId");
            c0984d.e(charSequenceSubSequence2);
            C0995g c0995gJ = c0984d.j();
            ((com.quizlet.themes.f) c0814p.j(b)).b.getClass();
            long j2 = com.quizlet.ui.resources.designsystem.generated.l.o;
            ((com.quizlet.themes.f) c0814p.j(b)).b.getClass();
            Map mapB = kotlin.collections.U.b(new Pair("iconId", new androidx.compose.foundation.text.Z(new androidx.compose.ui.text.v(j2, j2, 4), com.quizlet.features.practicetest.detail.composables.c.b)));
            androidx.compose.ui.text.L l2 = ((com.quizlet.themes.f) c0814p.j(b)).o;
            ((com.quizlet.themes.f) c0814p.j(b)).b.getClass();
            Q4.c(c0995gJ, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, ((com.quizlet.themes.j) c0814p.j(com.quizlet.themes.l.a)).p(), 7), 0L, 0L, null, 0L, null, j, 0, false, 0, 0, mapB, null, l2, c0814p, 0, 0, 97276);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.d(i, 10, qVar);
        }
    }

    public static final void b(com.quizlet.assembly.compose.modals.x modalState, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        com.quizlet.assembly.compose.modals.x xVar;
        Intrinsics.checkNotNullParameter(modalState, "modalState");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1188505427);
        int i2 = (c0814p.h(modalState) ? 4 : 2) | i | 48;
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            xVar = modalState;
        } else {
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            xVar = modalState;
            U5.b(xVar, nVar2, false, null, null, null, com.quizlet.features.practicetest.detail.composables.c.a, c0814p, (i2 & 14) | 1572920, 60);
            nVar = nVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.practicetest.detail.composables.d(xVar, nVar, i, 0);
        }
    }

    public static kotlinx.serialization.json.q c(Function1 builderAction) {
        kotlinx.serialization.json.b json = kotlinx.serialization.json.c.d;
        Intrinsics.checkNotNullParameter(json, "from");
        Intrinsics.checkNotNullParameter(builderAction, "builderAction");
        Intrinsics.checkNotNullParameter(json, "json");
        kotlinx.serialization.json.g gVar = new kotlinx.serialization.json.g();
        kotlinx.serialization.json.i iVar = json.a;
        gVar.a = iVar.a;
        gVar.b = iVar.e;
        gVar.c = iVar.b;
        gVar.d = iVar.c;
        gVar.e = iVar.d;
        String str = iVar.f;
        gVar.f = str;
        gVar.g = iVar.g;
        gVar.h = iVar.j;
        gVar.i = iVar.i;
        gVar.j = iVar.h;
        gVar.k = json.b;
        builderAction.invoke(gVar);
        if (gVar.e) {
            if (!Intrinsics.b(str, "    ")) {
                for (int i = 0; i < str.length(); i++) {
                    char cCharAt = str.charAt(i);
                    if (cCharAt != ' ' && cCharAt != '\t' && cCharAt != '\r' && cCharAt != '\n') {
                        throw new IllegalArgumentException("Only whitespace, tab, newline and carriage return are allowed as pretty print symbols. Had ".concat(str).toString());
                    }
                }
            }
        } else if (!Intrinsics.b(str, "    ")) {
            throw new IllegalArgumentException("Indent should not be specified when default printing mode is used");
        }
        kotlinx.serialization.json.i configuration = new kotlinx.serialization.json.i(gVar.a, gVar.c, gVar.d, gVar.e, gVar.b, gVar.f, gVar.g, gVar.j, gVar.i, gVar.h);
        androidx.camera.camera2.internal.p0 module = gVar.k;
        Intrinsics.checkNotNullParameter(configuration, "configuration");
        Intrinsics.checkNotNullParameter(module, "module");
        kotlinx.serialization.json.q qVar = new kotlinx.serialization.json.q(configuration, module);
        if (Intrinsics.b(module, kotlinx.serialization.modules.f.a)) {
            return qVar;
        }
        module.h(new androidx.room.s(configuration));
        return qVar;
    }

    public static final void d(StringBuilder builder, int i) {
        Intrinsics.checkNotNullParameter(builder, "builder");
        for (int i2 = 0; i2 < i; i2++) {
            builder.append("?");
            if (i2 < i - 1) {
                builder.append(",");
            }
        }
    }
}
