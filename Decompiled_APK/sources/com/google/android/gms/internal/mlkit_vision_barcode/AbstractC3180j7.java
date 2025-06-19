package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.j7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3180j7 {
    public static final void a(int i, int i2, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar) {
        androidx.compose.ui.q qVar2;
        int i3;
        androidx.compose.ui.q qVar3;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1840421486);
        int i4 = i2 & 1;
        if (i4 != 0) {
            i3 = i | 6;
            qVar2 = qVar;
        } else {
            qVar2 = qVar;
            i3 = (c0814p2.f(qVar2) ? 4 : 2) | i;
        }
        if ((i3 & 3) == 2 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
            qVar3 = qVar2;
        } else {
            qVar3 = i4 != 0 ? androidx.compose.ui.n.b : qVar2;
            c0814p = c0814p2;
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p2, R.string.scan_notes_artifact_error), qVar3, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.b)).o, c0814p, (i3 << 3) & ContentType.LONG_FORM_ON_DEMAND, 0, 65528);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.r(qVar3, i, i2, 1);
        }
    }

    public static androidx.glance.p b(androidx.glance.p pVar, androidx.glance.a aVar) {
        return pVar.d(new androidx.glance.d(aVar));
    }

    public static final io.ktor.util.d c(String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        return new io.ktor.util.d(str);
    }
}
