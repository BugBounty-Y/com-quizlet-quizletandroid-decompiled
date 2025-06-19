package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.navigation.compose.C1278k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.j, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3473j {
    public static final void a(com.quizlet.features.questiontypes.written.data.b gradingState, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(androidx.compose.foundation.layout.D.a, "<this>");
        Intrinsics.checkNotNullParameter(gradingState, "gradingState");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1752760719);
        if (((i | (c0814p2.f(gradingState) ? 32 : 16)) & 17) == 16 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.n();
            float f = com.quizlet.ui.resources.designsystem.generated.j.o;
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, 7);
            String strD = AbstractC3106b5.d(c0814p2, R.string.answer_label_close_enough_01);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long jL = ((com.quizlet.themes.b) c0814p2.j(b)).b.l();
            androidx.compose.runtime.B b2 = com.quizlet.themes.w.a;
            androidx.compose.material3.Q4.b(strD, qVarY, jL, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(b2)).j, c0814p2, 0, 0, 65528);
            com.quizlet.features.infra.models.a aVar = gradingState.a;
            com.quizlet.features.questiontypes.composables.a aVar2 = com.quizlet.features.questiontypes.composables.a.b;
            mVar.q();
            com.google.android.gms.internal.mlkit_vision_camera.F2.c(aVar2, androidx.compose.ui.platform.N.G(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.i, 7), "closeEnoughAnswer"), aVar, null, null, c0814p2, 6, 24);
            mVar.n();
            c0814p = c0814p2;
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p2, R.string.written_label_correct_answer), AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, 7), ((com.quizlet.themes.b) c0814p2.j(b)).b.f(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(b2)).j, c0814p, 0, 0, 65528);
            com.google.android.gms.internal.mlkit_vision_camera.F2.c(com.quizlet.features.questiontypes.composables.a.d, androidx.compose.ui.platform.N.G(nVar, "correctAnswer"), gradingState.b, null, null, c0814p, 54, 24);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1278k(gradingState, i, 23);
        }
    }

    public static final List b(List list) {
        int size = list.size();
        return size != 0 ? size != 1 ? Collections.unmodifiableList(new ArrayList(list)) : Collections.singletonList(CollectionsKt.L(list)) : kotlin.collections.K.a;
    }

    public static final Map c(Map map) {
        int size = map.size();
        if (size == 0) {
            return kotlin.collections.V.c();
        }
        if (size != 1) {
            return Collections.unmodifiableMap(new LinkedHashMap(map));
        }
        Map.Entry entry = (Map.Entry) CollectionsKt.K(map.entrySet());
        return Collections.singletonMap(entry.getKey(), entry.getValue());
    }
}
