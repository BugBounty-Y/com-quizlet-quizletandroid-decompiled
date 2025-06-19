package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3587b6;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.C4952k;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.C5048d;

/* loaded from: classes2.dex */
public abstract class R1 {
    public static final C5048d a(KSerializer elementSerializer) {
        Intrinsics.checkNotNullParameter(elementSerializer, "elementSerializer");
        return new C5048d(elementSerializer, 0);
    }

    public static final kotlinx.serialization.internal.F b(KSerializer valueSerializer) {
        kotlinx.serialization.internal.q0 keySerializer = kotlinx.serialization.internal.q0.a;
        Intrinsics.checkNotNullParameter(keySerializer, "keySerializer");
        Intrinsics.checkNotNullParameter(valueSerializer, "valueSerializer");
        return new kotlinx.serialization.internal.F(keySerializer, valueSerializer, 1);
    }

    public static final void c(int i, int i2, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, String text) {
        int i3;
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(text, "text");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-532378246);
        int i4 = (c0814p.f(text) ? 4 : 2) | i;
        int i5 = i2 & 2;
        if (i5 != 0) {
            i3 = i4 | 48;
        } else {
            i3 = i4 | (c0814p.f(qVar) ? 32 : 16);
        }
        if ((i3 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            qVar2 = i5 != 0 ? androidx.compose.ui.n.b : qVar;
            AbstractC3587b6.b(qVar2, 0L, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).H(), androidx.compose.runtime.internal.e.e(1567434673, new com.quizlet.assembly.compose.buttons.g0(text, 2), c0814p), c0814p, ((i3 >> 3) & 14) | 3072, 2);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.m(text, qVar2, i, i2, 2);
        }
    }

    public static final void d(boolean z, Function2 function2, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1818896922);
        int i2 = (c0814p.g(z) ? 4 : 2) | i | (c0814p.h(function2) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.work.impl.model.f.a(z, function2, c0814p, i2 & 126);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.internal.a(z, function2, i, 0);
        }
    }

    public static final KSerializer e(KSerializer kSerializer) {
        Intrinsics.checkNotNullParameter(kSerializer, "<this>");
        return kSerializer.getDescriptor().c() ? kSerializer : new kotlinx.serialization.internal.Y(kSerializer);
    }

    public static final void f(C4952k c4952k) {
        Intrinsics.checkNotNullParameter(c4952k, "<this>");
        kotlinx.serialization.internal.C c = kotlinx.serialization.internal.C.a;
    }

    public static final void g(kotlin.jvm.internal.N n) {
        Intrinsics.checkNotNullParameter(n, "<this>");
        kotlinx.serialization.internal.q0 q0Var = kotlinx.serialization.internal.q0.a;
    }
}
