package com.quizlet.features.match.viewmodel;

import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import androidx.lifecycle.p0;
import assistantMode.enums.QuestionType$Companion;
import assistantMode.enums.k;
import com.google.android.gms.internal.mlkit_vision_barcode.O6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.quizlet.features.match.data.A;
import com.quizlet.features.match.data.AbstractC4353i;
import com.quizlet.features.match.data.AbstractC4355k;
import com.quizlet.features.match.data.C4345a;
import com.quizlet.features.match.data.C4356l;
import com.quizlet.features.match.data.C4357m;
import com.quizlet.generated.enums.A1;
import com.quizlet.studiablemodels.MixedOptionMatchingStudiableQuestion;
import java.util.Iterator;
import java.util.UUID;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public abstract class c extends com.quizlet.viewmodel.b {
    public final com.quizlet.features.match.studyengine.g c;
    public final com.quizlet.features.match.logging.b d;
    public final X e;
    public final X f;
    public final Y g;
    public final X h;
    public final u i;
    public final String[] j;

    public c(com.quizlet.features.match.studyengine.g matchGameManager, com.quizlet.features.match.logging.b matchStudyModeLogger) {
        Intrinsics.checkNotNullParameter(matchGameManager, "matchGameManager");
        Intrinsics.checkNotNullParameter(matchStudyModeLogger, "matchStudyModeLogger");
        this.c = matchGameManager;
        this.d = matchStudyModeLogger;
        this.e = new X(1);
        this.f = new X(1);
        this.g = new Y();
        this.h = new X(1);
        this.i = l.b(new com.quizlet.featuregate.growthbook.a(this, 6));
        int size = ((com.quizlet.features.match.studyengine.e) matchGameManager).b.size();
        String[] strArr = new String[size];
        int i = 0;
        for (int i2 = 0; i2 < size; i2++) {
            strArr[i2] = UUID.randomUUID().toString();
        }
        this.j = strArr;
        this.g.j(new A(C()));
        this.e.j(Unit.a);
        com.quizlet.features.match.studyengine.e eVar = (com.quizlet.features.match.studyengine.e) this.c;
        Iterator it2 = eVar.b.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            int i3 = i + 1;
            if (i < 0) {
                B.p();
                throw null;
            }
            if (((AbstractC4355k) next) instanceof C4345a) {
                eVar.b();
                MixedOptionMatchingStudiableQuestion mixedOptionMatchingStudiableQuestion = eVar.d;
                if (mixedOptionMatchingStudiableQuestion == null) {
                    Intrinsics.m("currentQuestion");
                    throw null;
                }
                com.quizlet.features.match.logging.c cVar = new com.quizlet.features.match.logging.c(mixedOptionMatchingStudiableQuestion, i, null);
                String str = this.j[i];
                Intrinsics.checkNotNullExpressionValue(str, "get(...)");
                A1 a1 = A1.MOBILE_SCATTER;
                QuestionType$Companion questionType$Companion = k.Companion;
                P6.c(this.d, cVar, str, "view_start", null, a1, 8);
            }
            i = i3;
        }
    }

    public static a E(AbstractC4355k chosenCard, Object obj, Number number) {
        Intrinsics.checkNotNullParameter(chosenCard, "chosenCard");
        return (obj == null && chosenCard.a()) ? a.a : (!Intrinsics.b(obj, number) || chosenCard.a()) ? (obj == null || obj.equals(number) || !chosenCard.a()) ? a.d : a.c : a.b;
    }

    public final void B(O6 matchData) {
        Intrinsics.checkNotNullParameter(matchData, "matchData");
        Pair pairD = D(matchData);
        AbstractC4355k abstractC4355k = (AbstractC4355k) pairD.a;
        AbstractC4355k abstractC4355k2 = (AbstractC4355k) pairD.b;
        if (abstractC4355k.a() && abstractC4355k2.a()) {
            C4357m c4357m = C4357m.a;
            abstractC4355k.a = c4357m;
            abstractC4355k2.a = c4357m;
            E.A(p0.j(this), null, null, new b(this, abstractC4355k, abstractC4355k2, matchData, null), 3);
        }
    }

    public final AbstractC4353i C() {
        return (AbstractC4353i) this.i.getValue();
    }

    public abstract Pair D(O6 o6);

    public abstract AbstractC4353i F(com.quizlet.features.match.studyengine.g gVar);

    public final void G(O6 matchData) {
        Intrinsics.checkNotNullParameter(matchData, "matchData");
        Pair pairD = D(matchData);
        AbstractC4355k abstractC4355k = (AbstractC4355k) pairD.a;
        AbstractC4355k abstractC4355k2 = (AbstractC4355k) pairD.b;
        C4356l c4356l = C4356l.a;
        abstractC4355k.a = c4356l;
        abstractC4355k2.a = c4356l;
        C4345a cardItem = abstractC4355k instanceof C4345a ? (C4345a) abstractC4355k : abstractC4355k2 instanceof C4345a ? (C4345a) abstractC4355k2 : null;
        com.quizlet.features.match.studyengine.g gVar = this.c;
        if (cardItem != null) {
            com.quizlet.features.match.studyengine.e eVar = (com.quizlet.features.match.studyengine.e) gVar;
            eVar.getClass();
            Intrinsics.checkNotNullParameter(cardItem, "cardItem");
            int iIndexOf = eVar.b.indexOf(cardItem);
            eVar.b();
            MixedOptionMatchingStudiableQuestion mixedOptionMatchingStudiableQuestion = eVar.d;
            if (mixedOptionMatchingStudiableQuestion == null) {
                Intrinsics.m("currentQuestion");
                throw null;
            }
            com.quizlet.features.match.logging.c cVar = new com.quizlet.features.match.logging.c(mixedOptionMatchingStudiableQuestion, iIndexOf, null);
            String str = this.j[iIndexOf];
            Intrinsics.checkNotNullExpressionValue(str, "get(...)");
            P6.c(this.d, cVar, str, "view_end", null, null, 56);
        }
        com.quizlet.features.match.studyengine.e eVar2 = (com.quizlet.features.match.studyengine.e) gVar;
        eVar2.b();
        com.quizlet.features.match.studyengine.b bVar = eVar2.a;
        if (bVar.c.size() == bVar.d) {
            this.g.l(com.quizlet.features.match.data.B.a);
        } else {
            I();
        }
    }

    public final void H(O6 matchData) {
        Intrinsics.checkNotNullParameter(matchData, "matchData");
        Pair pairD = D(matchData);
        AbstractC4355k abstractC4355k = (AbstractC4355k) pairD.a;
        AbstractC4355k abstractC4355k2 = (AbstractC4355k) pairD.b;
        abstractC4355k.b(false);
        abstractC4355k2.b(false);
        I();
    }

    public final void I() {
        this.g.l(new A(C()));
    }

    public abstract void J();
}
