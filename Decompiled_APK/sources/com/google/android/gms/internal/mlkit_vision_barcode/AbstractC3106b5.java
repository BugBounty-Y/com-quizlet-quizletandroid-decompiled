package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.navigation.compose.C1279l;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.quizlet.features.flashcards.C4237k;
import java.util.Arrays;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.b5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3106b5 {
    public static final void a(boolean z, androidx.compose.ui.q qVar, Function1 function1, Function1 function12, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        androidx.compose.ui.q qVar2;
        int i4;
        Function1 function13;
        int i5;
        Function1 function14;
        int i6;
        Function1 function15;
        Function1 function16;
        Function1 function17;
        androidx.compose.ui.q qVar3;
        Function1 function18;
        int i7 = 2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(162071226);
        if ((i & 6) == 0) {
            i3 = i | (c0814p.g(z) ? 4 : 2);
        } else {
            i3 = i;
        }
        int i8 = i2 & 2;
        if (i8 != 0) {
            i4 = i3 | 48;
            qVar2 = qVar;
        } else {
            qVar2 = qVar;
            i4 = i3 | (c0814p.f(qVar2) ? 32 : 16);
        }
        int i9 = i2 & 4;
        if (i9 != 0) {
            i5 = i4 | 384;
            function13 = function1;
        } else {
            function13 = function1;
            i5 = i4 | (c0814p.h(function13) ? 256 : 128);
        }
        int i10 = i2 & 8;
        if (i10 != 0) {
            i6 = i5 | 3072;
            function14 = function12;
        } else {
            function14 = function12;
            i6 = i5 | (c0814p.h(function14) ? 2048 : 1024);
        }
        if ((i6 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            qVar3 = qVar2;
            function18 = function13;
            function17 = function14;
        } else {
            androidx.compose.ui.q qVar4 = i8 != 0 ? androidx.compose.ui.n.b : qVar2;
            androidx.compose.runtime.V v = C0804k.a;
            if (i9 != 0) {
                c0814p.X(210658106);
                Object objI = c0814p.I();
                if (objI == v) {
                    objI = new C4237k(10);
                    c0814p.i0(objI);
                }
                c0814p.p(false);
                function15 = (Function1) objI;
            } else {
                function15 = function13;
            }
            if (i10 != 0) {
                c0814p.X(210660346);
                Object objI2 = c0814p.I();
                if (objI2 == v) {
                    objI2 = new C4237k(11);
                    c0814p.i0(objI2);
                }
                function16 = (Function1) objI2;
                c0814p.p(false);
            } else {
                function16 = function14;
            }
            androidx.compose.ui.g gVar = androidx.compose.ui.b.n;
            C0380d c0380d = AbstractC0398m.a;
            com.quizlet.themes.m.g.s();
            C0392j c0392jG = AbstractC0398m.g(com.quizlet.ui.resources.designsystem.generated.j.h);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(qVar4.g(androidx.compose.foundation.layout.K0.c), "home_feed");
            c0814p.X(210674403);
            boolean z2 = ((i6 & 14) == 4) | ((i6 & 7168) == 2048) | ((i6 & 896) == 256);
            Object objI3 = c0814p.I();
            if (z2 || objI3 == v) {
                objI3 = new C1279l(z, function16, function15, i7);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            AbstractC3137f0.a(qVarG, null, null, c0392jG, gVar, null, false, (Function1) objI3, c0814p, 196608, OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_SERVICE_SPECIFIC_OFF);
            function17 = function16;
            qVar3 = qVar4;
            function18 = function15;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.flashcards.settings.ui.f(z, qVar3, function18, function17, i, i2);
        }
    }

    public static final String b(int i, int i2, Object[] objArr, InterfaceC0806l interfaceC0806l) {
        return AbstractC3097a5.a(interfaceC0806l).getQuantityString(i, i2, Arrays.copyOf(objArr, objArr.length));
    }

    public static final String c(int i, Object[] objArr, InterfaceC0806l interfaceC0806l) {
        return AbstractC3097a5.a(interfaceC0806l).getString(i, Arrays.copyOf(objArr, objArr.length));
    }

    public static final String d(InterfaceC0806l interfaceC0806l, int i) {
        return AbstractC3097a5.a(interfaceC0806l).getString(i);
    }

    public static final assistantMode.enums.m e(String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        assistantMode.enums.m mVar = assistantMode.enums.m.b;
        if (Intrinsics.b(value, "word")) {
            return mVar;
        }
        assistantMode.enums.m mVar2 = assistantMode.enums.m.c;
        if (Intrinsics.b(value, "definition")) {
            return mVar2;
        }
        assistantMode.enums.m mVar3 = assistantMode.enums.m.d;
        if (Intrinsics.b(value, "location")) {
            return mVar3;
        }
        throw new IllegalStateException(android.support.v4.media.session.a.B("Not a valid StudiableCardSideLabel value: (", value, ")"));
    }

    public static final assistantMode.enums.m f(com.quizlet.generated.enums.O1 o1) {
        Intrinsics.checkNotNullParameter(o1, "<this>");
        int i = com.quizlet.studiablemodels.h.a[o1.ordinal()];
        if (i == 1) {
            return assistantMode.enums.m.b;
        }
        if (i == 2) {
            return assistantMode.enums.m.c;
        }
        if (i == 3) {
            return assistantMode.enums.m.d;
        }
        throw new IllegalStateException("TermSide " + o1 + " has no corresponding StudiableCardSideLabel");
    }

    public static final com.quizlet.generated.enums.O1 g(assistantMode.enums.m mVar) {
        Intrinsics.checkNotNullParameter(mVar, "<this>");
        int iOrdinal = mVar.ordinal();
        if (iOrdinal == 0) {
            return com.quizlet.generated.enums.O1.WORD;
        }
        if (iOrdinal == 1) {
            return com.quizlet.generated.enums.O1.DEFINITION;
        }
        if (iOrdinal == 2) {
            return com.quizlet.generated.enums.O1.LOCATION;
        }
        throw new NoWhenBranchMatchedException();
    }
}
