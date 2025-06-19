package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import android.graphics.Color;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3745v5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Locale;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class S2 {
    public static final void a(androidx.compose.ui.q qVar, com.quizlet.features.settings.data.states.d dVar, String str, Function1 function1, com.quizlet.assembly.compose.input.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        com.quizlet.assembly.compose.input.n nVar2;
        String strE;
        C0814p c0814p;
        com.quizlet.assembly.compose.input.n nVar3;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-808245229);
        int i3 = i | (c0814p2.f(qVar) ? 4 : 2) | (c0814p2.f(dVar) ? 32 : 16) | (c0814p2.f(str) ? 256 : 128) | (c0814p2.h(function1) ? 2048 : 1024) | 8192;
        if ((i3 & 9363) == 9362 && c0814p2.x()) {
            c0814p2.Q();
            nVar3 = nVar;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            int i4 = i & 1;
            com.quizlet.features.settings.data.states.b bVar = com.quizlet.features.settings.data.states.b.a;
            if (i4 == 0 || c0814p2.w()) {
                i2 = i3 & (-57345);
                nVar2 = com.quizlet.assembly.compose.input.n.a;
            } else {
                c0814p2.Q();
                i2 = i3 & (-57345);
                nVar2 = nVar;
            }
            c0814p2.q();
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(qVar, "email_input_tag");
            String strD = AbstractC3106b5.d(c0814p2, R.string.new_email_label);
            c0814p2.X(-1271770602);
            if (dVar instanceof com.quizlet.features.settings.data.states.a) {
                strE = AbstractC3053s1.e(((com.quizlet.features.settings.data.states.a) dVar).a, (Context) c0814p2.j(AndroidCompositionLocals_androidKt.b));
            } else {
                if (!Intrinsics.b(dVar, bVar) && !Intrinsics.b(dVar, com.quizlet.features.settings.data.states.c.a)) {
                    throw new NoWhenBranchMatchedException();
                }
                strE = null;
            }
            String str2 = strE;
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC3745v5.b(str, function1, qVarG, null, strD, 0, 0, null, 0, 6, null, str2, false, null, null, dVar instanceof com.quizlet.features.settings.data.states.c, 0, nVar2, DefinitionKt.NO_Float_VALUE, null, null, c0814p, (i2 >> 6) & 126, 48, 0, 30922728);
            nVar3 = nVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.r(qVar, dVar, str, function1, nVar3, i);
        }
    }

    public static String b(int i) {
        Object[] objArr = {Integer.valueOf(Color.red(i)), Integer.valueOf(Color.green(i)), Integer.valueOf(Color.blue(i)), Double.valueOf(Color.alpha(i) / 255.0d)};
        int i2 = com.google.android.exoplayer2.util.a.a;
        return String.format(Locale.US, "rgba(%d,%d,%d,%.3f)", objArr);
    }
}
