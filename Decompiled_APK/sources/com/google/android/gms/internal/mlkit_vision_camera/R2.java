package com.google.android.gms.internal.mlkit_vision_camera;

import android.content.Context;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.text.C0995g;
import assistantMode.types.C1454a;
import assistantMode.types.QuestionElement;
import assistantMode.types.unions.TextAttribute;
import com.comscore.streaming.ContentType;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Regex;
import kotlin.text.StringsKt;
import org.wordpress.aztec.C5146b;
import org.wordpress.aztec.EnumC5145a;
import org.wordpress.aztec.spans.AztecTaskListSpan;
import org.wordpress.aztec.spans.AztecTaskListSpanAligned;

/* loaded from: classes2.dex */
public abstract class R2 {
    public static final void a(C0995g annotatedString, com.quizlet.features.questiontypes.fitb.ui.e inlineType, Function1 onInputTextChange, Function1 onDoneClick, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Intrinsics.checkNotNullParameter(annotatedString, "annotatedString");
        Intrinsics.checkNotNullParameter(inlineType, "inlineType");
        Intrinsics.checkNotNullParameter(onInputTextChange, "onInputTextChange");
        Intrinsics.checkNotNullParameter(onDoneClick, "onDoneClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1090035374);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(annotatedString) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= (i & 64) == 0 ? c0814p.f(inlineType) : c0814p.h(inlineType) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(onInputTextChange) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(onDoneClick) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.f(qVar) ? 16384 : 8192;
        }
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            b(annotatedString, qVar, androidx.compose.runtime.internal.e.e(-2094130138, new com.quizlet.assembly.compose.input.f(androidx.compose.runtime.internal.e.e(-1599641146, new com.quizlet.assembly.compose.menu.l(inlineType, onInputTextChange, onDoneClick, 19), c0814p), 8), c0814p), c0814p, ((i2 >> 9) & ContentType.LONG_FORM_ON_DEMAND) | (i2 & 14) | 384);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.p(annotatedString, inlineType, onInputTextChange, onDoneClick, qVar, i);
        }
    }

    public static final void b(C0995g annotatedString, androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Intrinsics.checkNotNullParameter(annotatedString, "annotatedString");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1611867808);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(annotatedString) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(dVar) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.X(-603781181);
            boolean z = ((i2 & 896) == 256) | ((i2 & 14) == 4);
            Object objI = c0814p.I();
            if (z || objI == C0804k.a) {
                objI = new com.quizlet.features.questionnaire.screens.d(1, dVar, annotatedString);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            AbstractC0897s.c(qVar, (Function2) objI, c0814p, (i2 >> 3) & 14, 0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, 29, annotatedString, qVar, dVar);
        }
    }

    public static final AztecTaskListSpan c(int i, EnumC5145a alignmentRendering, C5146b attributes, Context context, org.wordpress.aztec.formatting.e listStyle) {
        Intrinsics.checkNotNullParameter(alignmentRendering, "alignmentRendering");
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(listStyle, "listStyle");
        int iOrdinal = alignmentRendering.ordinal();
        if (iOrdinal == 0) {
            return new AztecTaskListSpanAligned(i, attributes, context, listStyle, null);
        }
        if (iOrdinal == 1) {
            return new AztecTaskListSpan(i, attributes, context, listStyle);
        }
        throw new NoWhenBranchMatchedException();
    }

    public static final QuestionElement d(assistantMode.types.B questionConfig, C1454a card) {
        k3 k3VarI;
        String strK;
        Intrinsics.checkNotNullParameter(questionConfig, "questionConfig");
        Intrinsics.checkNotNullParameter(card, "card");
        if (card.i == null) {
            int iOrdinal = questionConfig.a.c.ordinal();
            if (iOrdinal == 0) {
                k3VarI = card.i(assistantMode.enums.m.b);
            } else if (iOrdinal == 1) {
                k3VarI = card.i(assistantMode.enums.m.c);
            } else if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            String expectedAnswerText = k3VarI.e();
            Intrinsics.checkNotNullParameter(expectedAnswerText, "expectedAnswerText");
            String string = StringsKt.g0(expectedAnswerText).toString();
            if (string.length() <= 3) {
                strK = null;
            } else {
                List listG = new Regex("\\s+").g(0, string);
                if (listG.size() >= 3) {
                    strK = android.support.v4.media.session.a.k(CollectionsKt.S(CollectionsKt.l0(listG, kotlin.ranges.l.h(0, (int) Math.floor(listG.size() / 3.0d))), " ", null, null, null, 62), " ________");
                } else {
                    strK = string.charAt(0) + "________";
                }
            }
            if (strK != null) {
                return new QuestionElement(kotlin.collections.A.b(new TextAttribute(strK, k3VarI.c(), null)));
            }
        }
        return null;
    }
}
