package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.layout.C0888i;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import assistantMode.types.AssistantGradingSettingsSuggestion;
import com.quizlet.studiablemodels.StudiableImage;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Regex;

/* loaded from: classes2.dex */
public abstract class l3 {
    public static final void a(StudiableImage image, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(image, "image");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-97240661);
        if ((i & 6) == 0) {
            i2 = (c0814p2.h(image) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        int i3 = i2 | 48;
        if ((i & 384) == 0) {
            i3 |= c0814p2.h(function1) ? 256 : 128;
        }
        if ((i3 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            qVar = androidx.compose.ui.n.b;
            androidx.compose.runtime.V v = C0804k.a;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p2, 0);
            int i4 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, bA, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p2, i4, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            androidx.compose.ui.q qVarG = androidx.compose.foundation.layout.C.a(androidx.compose.ui.platform.N.G(qVar, "imageView"), 1.0f).g(androidx.compose.foundation.layout.K0.c);
            com.quizlet.themes.m.g.p();
            androidx.compose.ui.q qVarW = AbstractC0382e.w(qVarG, com.quizlet.ui.resources.designsystem.generated.j.j, DefinitionKt.NO_Float_VALUE, 2);
            Unit unit = Unit.a;
            c0814p2.X(953419968);
            boolean zH = ((i3 & 896) == 256) | c0814p2.h(image);
            Object objI = c0814p2.I();
            if (zH || objI == v) {
                objI = new com.quizlet.features.questiontypes.selfassessment.ui.c(function1, image, null);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            r3.a(image.a(), null, androidx.compose.ui.input.pointer.v.a(qVarW, unit, (Function2) objI), null, C0888i.b, null, c0814p2, 1572912, 1976);
            k3.a(null, null, null, null, c0814p2, 0, 15);
            c0814p = c0814p2;
            c0814p.p(true);
        }
        androidx.compose.ui.q qVar2 = qVar;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(i, 0, image, qVar2, function1);
        }
    }

    public static final boolean b(Regex regex, String str) {
        if (str == null) {
            return false;
        }
        Boolean boolValueOf = regex != null ? Boolean.valueOf(regex.a(str)) : null;
        if (boolValueOf != null) {
            return boolValueOf.booleanValue();
        }
        return false;
    }

    public static final AssistantGradingSettingsSuggestion c(grading.core.e eVar) {
        boolean z;
        if (eVar == null) {
            return null;
        }
        int iOrdinal = eVar.a.ordinal();
        if (iOrdinal == 0) {
            z = true;
        } else {
            if (iOrdinal != 1) {
                throw new NoWhenBranchMatchedException();
            }
            z = false;
        }
        int iOrdinal2 = eVar.b.ordinal();
        if (iOrdinal2 == 0) {
            return new AssistantGradingSettingsSuggestion(Boolean.valueOf(z), (Boolean) null, (Boolean) null, (Boolean) null, 14);
        }
        if (iOrdinal2 == 1) {
            return new AssistantGradingSettingsSuggestion((Boolean) null, Boolean.valueOf(z), (Boolean) null, (Boolean) null, 13);
        }
        if (iOrdinal2 == 2) {
            return new AssistantGradingSettingsSuggestion((Boolean) null, (Boolean) null, Boolean.valueOf(z), (Boolean) null, 11);
        }
        if (iOrdinal2 == 3) {
            return new AssistantGradingSettingsSuggestion((Boolean) null, (Boolean) null, (Boolean) null, Boolean.valueOf(z), 7);
        }
        throw new NoWhenBranchMatchedException();
    }
}
