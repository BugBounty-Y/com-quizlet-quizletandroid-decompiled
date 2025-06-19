package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.v4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3549v4 {
    public static final void a(androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        androidx.compose.ui.n nVar2;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(617446393);
        if (((i | 6) & 3) == 2 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.s();
            c0814p = c0814p2;
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p2, R.string.learn_onboarding_set_goal), AbstractC0382e.y(nVar3, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.h, 7), ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.b)).i, c0814p, 0, 0, 65528);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.folders.changetags.composables.a(nVar2, i, 4);
        }
    }
}
