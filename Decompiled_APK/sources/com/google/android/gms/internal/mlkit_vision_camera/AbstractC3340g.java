package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.R4;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.IOException;
import java.io.Reader;
import java.io.StringWriter;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.g, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3340g {
    public static final void a(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 function0, Function0 function02) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(299355164);
        if ((((c0814p2.f(qVar) ? 4 : 2) | i | (c0814p2.h(function0) ? 32 : 16) | (c0814p2.h(function02) ? 256 : 128)) & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(AbstractC0382e.p(androidx.compose.foundation.layout.K0.q(qVar, DefinitionKt.NO_Float_VALUE, 360, 1), 2), "toast");
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            c0814p = c0814p2;
            R4.a(qVarG, null, ((com.quizlet.themes.b) c0814p2.j(b)).L(), 0L, ((com.quizlet.themes.b) c0814p2.j(b)).v(), null, false, null, null, null, androidx.compose.runtime.internal.e.e(-727915486, new com.quizlet.features.notes.upload.composables.upload.b(0, function02, function0), c0814p2), c0814p, 0, 1002);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.flashcards.views.composables.k(qVar, function0, function02, i);
        }
    }

    public static final String b(Reader reader) throws IOException {
        Intrinsics.checkNotNullParameter(reader, "<this>");
        StringWriter out = new StringWriter();
        Intrinsics.checkNotNullParameter(reader, "<this>");
        Intrinsics.checkNotNullParameter(out, "out");
        char[] cArr = new char[8192];
        int i = reader.read(cArr);
        while (i >= 0) {
            out.write(cArr, 0, i);
            i = reader.read(cArr);
        }
        String string = out.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }

    public static final androidx.glance.p c(androidx.glance.p pVar, Function1 function1) {
        androidx.glance.semantics.a aVar = new androidx.glance.semantics.a();
        function1.invoke(aVar);
        return pVar.d(new androidx.glance.semantics.b(aVar));
    }
}
