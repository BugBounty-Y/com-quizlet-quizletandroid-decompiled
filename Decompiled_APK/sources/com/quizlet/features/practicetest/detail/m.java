package com.quizlet.features.practicetest.detail;

import com.comscore.streaming.EventType;
import com.quizlet.features.practicetest.detail.data.C4398a;
import com.quizlet.features.practicetest.detail.data.C4400c;
import com.quizlet.features.practicetest.detail.data.C4402e;
import com.quizlet.features.practicetest.takingtest.data.o;
import com.quizlet.features.practicetest.takingtest.data.p;
import com.quizlet.features.practicetest.takingtest.data.v;
import com.quizlet.features.universaluploadflow.data.C4460i;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final /* synthetic */ class m implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;

    public /* synthetic */ m(int i, Function1 function1) {
        this.a = i;
        this.b = function1;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.invoke(C4398a.a);
                break;
            case 1:
                this.b.invoke(C4398a.a);
                break;
            case 2:
                this.b.invoke(com.quizlet.features.practicetest.detail.data.j.a);
                break;
            case 3:
                this.b.invoke(C4402e.a);
                break;
            case 4:
                this.b.invoke(C4400c.a);
                break;
            case 5:
                this.b.invoke(com.quizlet.features.practicetest.results.data.g.a);
                break;
            case 6:
                this.b.invoke(com.quizlet.features.practicetest.results.data.f.a);
                break;
            case 7:
                this.b.invoke(com.quizlet.features.practicetest.results.data.f.a);
                break;
            case 8:
                this.b.invoke(com.quizlet.features.practicetest.results.data.l.a);
                break;
            case 9:
                this.b.invoke(com.quizlet.features.practicetest.results.data.f.a);
                break;
            case 10:
                this.b.invoke(com.quizlet.features.practicetest.results.data.f.a);
                break;
            case 11:
                this.b.invoke(v.a);
                break;
            case 12:
                this.b.invoke(p.a);
                break;
            case 13:
                this.b.invoke(o.a);
                break;
            case 14:
                this.b.invoke(com.quizlet.features.questiontypes.truefalse.c.b);
                break;
            case 15:
                this.b.invoke(com.quizlet.features.questiontypes.truefalse.c.a);
                break;
            case 16:
                this.b.invoke(Boolean.TRUE);
                break;
            case 17:
                this.b.invoke(Boolean.FALSE);
                break;
            case 18:
                this.b.invoke(C4460i.a);
                break;
            case 19:
                this.b.invoke(com.quizlet.features.universaluploadflow.flashcards.data.e.a);
                break;
            case 20:
                this.b.invoke(com.quizlet.features.universaluploadflow.flashcards.data.c.a);
                break;
            case 21:
                this.b.invoke(com.quizlet.features.universaluploadflow.pastetext.data.e.a);
                break;
            case EventType.WINDOW_STATE /* 22 */:
                this.b.invoke(com.quizlet.features.universaluploadflow.pastetext.data.b.a);
                break;
            case EventType.AUDIO /* 23 */:
                this.b.invoke(com.quizlet.features.universaluploadflow.pastetext.data.a.a);
                break;
            case EventType.VIDEO /* 24 */:
                this.b.invoke(com.quizlet.login.intro.data.c.a);
                break;
            case EventType.SUBS /* 25 */:
                this.b.invoke(com.quizlet.login.intro.data.c.a);
                break;
            case EventType.CDN /* 26 */:
                this.b.invoke(com.quizlet.login.intro.data.d.a);
                break;
            case 27:
                this.b.invoke(com.quizlet.login.intro.data.b.a);
                break;
            case 28:
                this.b.invoke(com.quizlet.login.intro.data.a.a);
                break;
            default:
                this.b.invoke(com.quizlet.login.intro.data.i.a);
                break;
        }
        return Unit.a;
    }
}
