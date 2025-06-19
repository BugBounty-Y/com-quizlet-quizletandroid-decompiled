package com.quizlet.features.questiontypes.mcq;

import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import assistantMode.enums.EnumC1452f;
import com.google.android.gms.internal.mlkit_vision_camera.X2;
import com.quizlet.diagrams.ui.DiagramJSBridge;
import com.quizlet.eventlogger.features.basequestion.QuestionEventLogger;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import com.quizlet.generated.enums.A1;
import com.quizlet.studiablemodels.LocationQuestionSectionData;
import com.quizlet.studiablemodels.MultipleChoiceStudiableQuestion;
import com.quizlet.studiablemodels.QuestionSectionData;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5041z;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.Y;
import kotlinx.coroutines.flow.Z;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class l extends w0 implements a {
    public final com.quizlet.data.repository.studysetwithcreator.d b;
    public final com.quizlet.quizletandroid.ui.studymodes.grader.b c;
    public final QuestionEventLogger d;
    public final com.quizlet.quizletandroid.managers.audio.h e;
    public final com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a f;
    public final DiagramJSBridge g;
    public final QuestionSettings h;
    public final MultipleChoiceStudiableQuestion i;
    public final long j;
    public final A1 k;
    public final boolean l;
    public final boolean m;
    public final String n;
    public final s0 o;
    public final Z p;
    public final s0 q;
    public final Z r;
    public final s0 s;
    public final Z t;
    public final d0 u;
    public final Y v;
    public EnumC1452f w;
    public boolean x;

    /* JADX WARN: Removed duplicated region for block: B:27:0x014e  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0188 A[EDGE_INSN: B:117:0x0188->B:32:0x0188 BREAK  A[LOOP:6: B:20:0x0139->B:118:?]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public l(androidx.lifecycle.m0 r21, com.quizlet.data.repository.studysetwithcreator.d r22, com.quizlet.quizletandroid.ui.studymodes.grader.b r23, com.quizlet.eventlogger.features.basequestion.QuestionEventLogger r24, com.quizlet.quizletandroid.managers.audio.h r25, com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a r26, com.google.mlkit.common.sdkinternal.b r27) {
        /*
            Method dump skipped, instructions count: 742
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.questiontypes.mcq.l.<init>(androidx.lifecycle.m0, com.quizlet.data.repository.studysetwithcreator.d, com.quizlet.quizletandroid.ui.studymodes.grader.b, com.quizlet.eventlogger.features.basequestion.QuestionEventLogger, com.quizlet.quizletandroid.managers.audio.h, com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a, com.google.mlkit.common.sdkinternal.b):void");
    }

    public static final Unit A(l lVar, boolean z) {
        if (!(((o) lVar.o.getValue()) instanceof n)) {
            return Unit.a;
        }
        Boolean boolValueOf = Boolean.valueOf(z);
        s0 s0Var = lVar.q;
        s0Var.getClass();
        s0Var.m(null, boolValueOf);
        Unit unit = Unit.a;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        return unit;
    }

    public final void B(X2 event) {
        Intrinsics.checkNotNullParameter(event, "event");
        if (event instanceof q) {
            E.A(p0.j(this), null, null, new j(this, ((q) event).a, null), 3);
            return;
        }
        if (!(event instanceof s)) {
            if (event instanceof t) {
                C();
                return;
            } else if (event instanceof r) {
                E.A(p0.j(this), null, null, new h(this, null), 3);
                return;
            } else {
                if (!(event instanceof p)) {
                    throw new NoWhenBranchMatchedException();
                }
                E.A(p0.j(this), null, null, new g(this, null), 3);
                return;
            }
        }
        s sVar = (s) event;
        if (this.x) {
            return;
        }
        List<QuestionSectionData> list = this.i.c;
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        for (QuestionSectionData questionSectionData : list) {
            Intrinsics.e(questionSectionData, "null cannot be cast to non-null type com.quizlet.studiablemodels.LocationQuestionSectionData");
            arrayList.add((LocationQuestionSectionData) questionSectionData);
        }
        Iterator it2 = arrayList.iterator();
        int i = 0;
        while (true) {
            if (!it2.hasNext()) {
                i = -1;
                break;
            } else if (((LocationQuestionSectionData) it2.next()).a == sVar.a.a) {
                break;
            } else {
                i++;
            }
        }
        E.A(p0.j(this), null, null, new j(this, i, null), 3);
    }

    public final void C() {
        if (this.i.f.a()) {
            return;
        }
        E.A(p0.j(this), new androidx.compose.ui.text.font.o(C5041z.a, 3), null, new i(this, null), 2);
    }
}
