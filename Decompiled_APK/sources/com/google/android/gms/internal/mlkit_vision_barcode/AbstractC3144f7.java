package com.google.android.gms.internal.mlkit_vision_barcode;

import android.view.View;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.Fragment;
import com.quizlet.quizletandroid.R;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.f7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3144f7 {
    public static final void a(androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        androidx.compose.ui.n nVar2;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1646406266);
        if (((i | 6) & 3) == 2 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            String strD = AbstractC3106b5.d(c0814p2, R.string.magic_notes_removed_content_artifact);
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).j;
            long jF = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.f();
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar3, 1.0f);
            com.quizlet.themes.m.g.p();
            c0814p = c0814p2;
            androidx.compose.material3.Q4.b(strD, AbstractC0382e.u(qVarC, com.quizlet.ui.resources.designsystem.generated.j.j), jF, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65016);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.folders.changetags.composables.a(nVar2, i, 2);
        }
    }

    public static final Fragment b(View view) {
        Fragment fragmentG = AbstractC1136h0.G(view);
        if (fragmentG != null) {
            return fragmentG;
        }
        throw new IllegalStateException("View " + view + " does not have a Fragment set");
    }
}
