package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0384f;
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
import assistantMode.refactored.modelTypes.CardSideDistractor;
import assistantMode.refactored.modelTypes.TextValue;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3155h0;
import com.quizlet.features.achievements.ui.composables.C4219f;
import com.quizlet.studiablemodels.StudiableAudio;
import com.quizlet.studiablemodels.StudiableImage;
import com.quizlet.studiablemodels.StudiableText;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Set;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class o3 {
    public static final void a(StudiableImage studiableImage, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1827250156);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(studiableImage) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function1) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            androidx.compose.ui.q qVarH = AbstractC0382e.h(androidx.compose.ui.platform.N.G(androidx.compose.ui.n.b, "imageView"));
            com.quizlet.themes.m.g.p();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(qVarH, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.j, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            Unit unit = Unit.a;
            c0814p.X(-1610720931);
            boolean zH = ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32) | c0814p.h(studiableImage);
            Object objI = c0814p.I();
            if (zH || objI == v) {
                objI = new com.quizlet.features.questiontypes.selfassessment.ui.f(function1, studiableImage, null);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            r3.a(studiableImage.a(), null, androidx.compose.ui.input.pointer.v.a(qVarY, unit, (Function2) objI), null, C0888i.b, null, c0814p, 1572912, 1976);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(studiableImage, function1, i, 21);
        }
    }

    public static final void b(int i, StudiableText text, StudiableImage image, StudiableAudio studiableAudio, androidx.compose.ui.q qVar, Function0 function0, Function1 function1, Function1 function12, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        int i4;
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(image, "image");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1428888490);
        if ((i2 & 6) == 0) {
            i3 = (c0814p.d(i) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i3 |= c0814p.h(text) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i3 |= c0814p.h(image) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i3 |= c0814p.h(studiableAudio) ? 2048 : 1024;
        }
        int i5 = i3 | 24576;
        if ((196608 & i2) == 0) {
            i5 |= c0814p.h(function0) ? 131072 : 65536;
        }
        if ((1572864 & i2) == 0) {
            i5 |= c0814p.h(function1) ? 1048576 : 524288;
        }
        if ((12582912 & i2) == 0) {
            i5 |= c0814p.h(function12) ? 8388608 : 4194304;
        }
        if ((4793491 & i5) == 4793490 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            int i6 = i5 >> 12;
            C0384f c0384f = AbstractC0398m.c;
            androidx.compose.ui.g gVar = androidx.compose.ui.b.m;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(c0384f, gVar, c0814p, 0);
            int i7 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            int i8 = i5;
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, nVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, bA, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i7))) {
                android.support.v4.media.session.a.z(i7, c0814p, i7, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            Set set = androidx.compose.material3.windowsizeclass.c.b;
            if (i == 0) {
                c0814p.X(-1941493673);
                androidx.compose.ui.q qVarA = androidx.compose.foundation.layout.C.a(nVar, 1.0f);
                com.quizlet.themes.m.g.p();
                i4 = i6;
                androidx.compose.ui.q qVarW = AbstractC0382e.w(qVarA, com.quizlet.ui.resources.designsystem.generated.j.j, DefinitionKt.NO_Float_VALUE, 2);
                androidx.compose.foundation.layout.B bA2 = androidx.compose.foundation.layout.A.a(c0384f, gVar, c0814p, 0);
                int i9 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
                androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarW);
                c0814p.b0();
                if (c0814p.O) {
                    c0814p.k(c0913i);
                } else {
                    c0814p.l0();
                }
                C0776c.E(c0814p, bA2, c0912h);
                C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i9))) {
                    android.support.v4.media.session.a.z(i9, c0814p, i9, c0912h3);
                }
                C0776c.E(c0814p, qVarC2, c0912h4);
                a(image, function1, c0814p, ((i8 >> 6) & 14) | ((i8 >> 15) & ContentType.LONG_FORM_ON_DEMAND));
                c(text, c0814p, (i8 >> 3) & 14);
                c0814p.p(true);
                c0814p.p(false);
            } else {
                i4 = i6;
                c0814p.X(-1941163802);
                androidx.compose.ui.q qVarA2 = androidx.compose.foundation.layout.C.a(nVar, 1.0f);
                com.quizlet.themes.m.g.q();
                androidx.compose.ui.q qVarU = AbstractC0382e.u(qVarA2, com.quizlet.ui.resources.designsystem.generated.j.i);
                androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.k, c0814p, 48);
                int i10 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L3 = c0814p.l();
                androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, qVarU);
                c0814p.b0();
                if (c0814p.O) {
                    c0814p.k(c0913i);
                } else {
                    c0814p.l0();
                }
                C0776c.E(c0814p, g0B, c0912h);
                C0776c.E(c0814p, interfaceC0803j0L3, c0912h2);
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i10))) {
                    android.support.v4.media.session.a.z(i10, c0814p, i10, c0912h3);
                }
                C0776c.E(c0814p, qVarC3, c0912h4);
                a(image, function1, c0814p, ((i8 >> 6) & 14) | ((i8 >> 15) & ContentType.LONG_FORM_ON_DEMAND));
                c(text, c0814p, (i8 >> 3) & 14);
                c0814p.p(true);
                c0814p.p(false);
            }
            k3.a(null, studiableAudio, function0, function12, c0814p, ((i8 >> 6) & ContentType.LONG_FORM_ON_DEMAND) | ((i8 >> 9) & 896) | (i4 & 7168), 1);
            c0814p.p(true);
            qVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4219f(i, text, image, studiableAudio, qVar2, function0, function1, function12, i2);
        }
    }

    public static final void c(StudiableText studiableText, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-207005145);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(studiableText) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarR = androidx.compose.foundation.layout.K0.r(androidx.compose.foundation.layout.K0.t(androidx.compose.foundation.layout.K0.c(androidx.compose.ui.platform.N.G(androidx.compose.ui.n.b, "textView"), 1.0f), 3), 3);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            mVar.u();
            AbstractC3155h0.a(studiableText.a, studiableText.c, studiableText.b, AbstractC0382e.y(qVarR, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, 5), DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, null, 0, 2, null, null, c0814p, 805306374, 3552);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.t(studiableText, i, 3);
        }
    }

    public static final ArrayList d(assistantMode.utils.parsing.a aVar) {
        Intrinsics.checkNotNullParameter(aVar, "<this>");
        ArrayList arrayList = aVar.b;
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            if (!((assistantMode.utils.parsing.b) next).b) {
                arrayList2.add(next);
            }
        }
        return arrayList2;
    }

    public static final CardSideDistractor e(assistantMode.utils.parsing.b bVar, String languageCode) {
        Intrinsics.checkNotNullParameter(bVar, "<this>");
        Intrinsics.checkNotNullParameter(languageCode, "languageCode");
        Intrinsics.checkNotNullParameter(bVar, "<this>");
        return new CardSideDistractor(kotlin.collections.A.b(new TextValue(bVar.a, languageCode, null, null, null)));
    }
}
