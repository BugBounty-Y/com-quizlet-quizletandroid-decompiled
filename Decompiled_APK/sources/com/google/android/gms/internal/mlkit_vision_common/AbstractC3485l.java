package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.navigation.compose.C1278k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.FileNotFoundException;
import java.io.IOException;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.l, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3485l {
    public static final void a(com.quizlet.features.questiontypes.written.data.d gradingState, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(androidx.compose.foundation.layout.D.a, "<this>");
        Intrinsics.checkNotNullParameter(gradingState, "gradingState");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(33039962);
        if (((i | (c0814p2.f(gradingState) ? 32 : 16)) & 17) == 16 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.n();
            float f = com.quizlet.ui.resources.designsystem.generated.j.o;
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, 7);
            String strD = AbstractC3106b5.d(c0814p2, R.string.answer_label_do_not_know);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jF = ((com.quizlet.themes.b) c0814p2.j(b)).b.f();
            androidx.compose.runtime.B b2 = com.quizlet.themes.w.a;
            androidx.compose.material3.Q4.b(strD, qVarY, jF, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(b2)).j, c0814p2, 0, 0, 65528);
            com.quizlet.features.infra.models.a aVar = new com.quizlet.features.infra.models.a(AbstractC3106b5.d(c0814p2, R.string.do_not_know_skipped_answer), null, null, false);
            com.quizlet.features.questiontypes.composables.a aVar2 = com.quizlet.features.questiontypes.composables.a.d;
            mVar.q();
            com.google.android.gms.internal.mlkit_vision_camera.F2.c(aVar2, androidx.compose.ui.platform.N.G(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.i, 7), "doNotKnowAnswer"), aVar, null, null, c0814p2, 6, 24);
            mVar.n();
            c0814p = c0814p2;
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p2, R.string.written_label_correct_answer), AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, 7), ((com.quizlet.themes.b) c0814p2.j(b)).b.l(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(b2)).j, c0814p, 0, 0, 65528);
            com.google.android.gms.internal.mlkit_vision_camera.F2.c(com.quizlet.features.questiontypes.composables.a.b, androidx.compose.ui.platform.N.G(nVar, "correctAnswer"), gradingState.a, null, null, c0814p, 54, 24);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1278k(gradingState, i, 25);
        }
    }

    public static void b(okio.n nVar, okio.x file) throws IOException {
        if (nVar.p(file)) {
            return;
        }
        Intrinsics.checkNotNullParameter(file, "file");
        try {
            nVar.D(file, false).close();
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception unused) {
        }
    }

    public static final void c(okio.n nVar, okio.x xVar) throws IOException {
        try {
            IOException iOException = null;
            for (okio.x xVar2 : nVar.q(xVar)) {
                try {
                    if (nVar.y(xVar2).c) {
                        c(nVar, xVar2);
                    }
                    nVar.j(xVar2);
                } catch (IOException e) {
                    if (iOException == null) {
                        iOException = e;
                    }
                }
            }
            if (iOException != null) {
                throw iOException;
            }
        } catch (FileNotFoundException unused) {
        }
    }
}
