package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.fragment.app.Fragment;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.assembly.compose.buttons.C4079d;
import com.quizlet.assembly.compose.buttons.C4097w;
import com.quizlet.features.infra.legacyadapter.RecyclerViewFragment;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.q6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3707q6 {
    public static final void a(String focusedLearnPrimaryActionButtonText, Function0 focusedLearnPrimaryActionButtonOnClick, androidx.compose.ui.graphics.painter.b bVar, String focusedLearnSecondaryActionButtonText, Function0 focusedLearnSecondaryActionButtonOnClick, androidx.compose.ui.graphics.painter.b bVar2, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(focusedLearnPrimaryActionButtonText, "focusedLearnPrimaryActionButtonText");
        Intrinsics.checkNotNullParameter(focusedLearnPrimaryActionButtonOnClick, "focusedLearnPrimaryActionButtonOnClick");
        Intrinsics.checkNotNullParameter(focusedLearnSecondaryActionButtonText, "focusedLearnSecondaryActionButtonText");
        Intrinsics.checkNotNullParameter(focusedLearnSecondaryActionButtonOnClick, "focusedLearnSecondaryActionButtonOnClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1032202382);
        int i2 = i | (c0814p.f(focusedLearnPrimaryActionButtonText) ? 4 : 2) | (c0814p.h(focusedLearnPrimaryActionButtonOnClick) ? 32 : 16) | (c0814p.h(bVar) ? 256 : 128) | (c0814p.f(focusedLearnSecondaryActionButtonText) ? 2048 : 1024) | (c0814p.h(focusedLearnSecondaryActionButtonOnClick) ? 16384 : 8192) | (c0814p.h(bVar2) ? 131072 : 65536) | (c0814p.f(qVar) ? 1048576 : 524288);
        if ((i2 & 599187) == 599186 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.test_result_next_steps), null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.f(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).j, c0814p, 0, 0, 65530);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), 1.0f);
            C4097w c4097w = C4097w.a;
            W4.a(focusedLearnPrimaryActionButtonText, qVarC2, focusedLearnPrimaryActionButtonOnClick, false, null, c4097w, null, bVar, null, false, c0814p, (i2 & 14) | 805306368 | ((i2 << 3) & 896) | ((i2 << 15) & 29360128), 344);
            mVar.s();
            Y4.a(focusedLearnSecondaryActionButtonText, androidx.compose.foundation.layout.K0.c(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), 1.0f), focusedLearnSecondaryActionButtonOnClick, false, false, null, null, 0L, 0L, c4097w, bVar2, null, false, c0814p, ((i2 >> 9) & 14) | ((i2 >> 6) & 896), ((i2 >> 15) & 14) | 384, 2552);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4079d(focusedLearnPrimaryActionButtonText, focusedLearnPrimaryActionButtonOnClick, bVar, focusedLearnSecondaryActionButtonText, focusedLearnSecondaryActionButtonOnClick, bVar2, qVar, i, 6);
        }
    }

    public static final Object b(RecyclerViewFragment recyclerViewFragment, Class clazz) {
        Intrinsics.checkNotNullParameter(recyclerViewFragment, "<this>");
        Intrinsics.checkNotNullParameter(clazz, "clazz");
        Context context = recyclerViewFragment.getContext();
        if (context != null && clazz.isInstance(context)) {
            return context;
        }
        Fragment parentFragment = recyclerViewFragment.getParentFragment();
        if (parentFragment == null || !clazz.isInstance(parentFragment)) {
            throw new IllegalStateException("Either host Context or parent Fragment must implement ".concat(clazz.getSimpleName()));
        }
        return parentFragment;
    }
}
