package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint;

import androidx.lifecycle.p0;
import androidx.navigation.H;
import com.comscore.streaming.EventType;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import com.quizlet.eventlogger.features.search.SearchEventsEventLog;
import com.quizlet.features.match.data.X;
import com.quizlet.generated.enums.EnumC4466a1;
import com.quizlet.learn.data.C;
import com.quizlet.learn.viewmodel.G;
import com.quizlet.partskit.widgets.QProgressBar;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.MatchEndGameFragment;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.MatchGameFragment;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.MatchStartGameFragment;
import com.quizlet.quizletandroid.ui.studymodes.testmode.start.InterfaceC4758b;
import com.quizlet.quizletandroid.ui.subject.SubjectCategoryActivity;
import com.quizlet.search.viewmodels.C4805k;
import com.quizlet.search.viewmodels.K;
import com.quizlet.search.viewmodels.M;
import com.quizlet.studiablemodels.StudiableMeteringData;
import com.quizlet.studiablemodels.StudiableStep;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final /* synthetic */ class l extends C4956o implements Function0 {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ l(int i, Object obj, Class cls, String str, String str2, int i2, int i3) {
        super(i, i2, cls, obj, str, str2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        StudiableMeteringData studiableMeteringData;
        StudiableMeteringData studiableMeteringData2;
        String title;
        s0 s0Var;
        Object value;
        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.i iVar = com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.i.a;
        switch (this.a) {
            case 0:
                G g = (G) this.receiver;
                StudiableStep studiableStep = g.l1;
                if (studiableStep != null && (studiableMeteringData = studiableStep.a) != null) {
                    com.quizlet.features.infra.basestudy.manager.f fVar = g.Z;
                    g.w.c(fVar.u, fVar.t, studiableMeteringData);
                }
                break;
            case 1:
                G g2 = (G) this.receiver;
                StudiableStep studiableStep2 = g2.l1;
                if (studiableStep2 != null && (studiableMeteringData2 = studiableStep2.a) != null) {
                    com.quizlet.features.infra.basestudy.manager.f fVar2 = g2.Z;
                    g2.w.d(fVar2.u, fVar2.t, studiableMeteringData2);
                }
                break;
            case 2:
                ((G) this.receiver).X();
                break;
            case 3:
                ((G) this.receiver).D();
                break;
            case 4:
                G g3 = (G) this.receiver;
                g3.getClass();
                com.quizlet.learn.logging.c[] cVarArr = com.quizlet.learn.logging.c.a;
                com.quizlet.learn.logging.b[] bVarArr = com.quizlet.learn.logging.b.a;
                com.quizlet.features.infra.basestudy.manager.f fVar3 = g3.Z;
                com.quizlet.features.infra.basestudy.manager.f.j(fVar3, "review_flashcards", 4);
                int i = fVar3.q;
                DBStudySet dBStudySetE = fVar3.e();
                g3.M.j(new C(i, fVar3.l, fVar3.m, (dBStudySetE == null || (title = dBStudySetE.getTitle()) == null) ? "" : title, fVar3.k));
                break;
            case 5:
                ((G) this.receiver).T();
                break;
            case 6:
                ((G) this.receiver).V();
                break;
            case 7:
                ((com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.i) this.receiver).j.h(com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.h.a);
                break;
            case 8:
                ((com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.i) this.receiver).j.h(iVar);
                break;
            case 9:
                ((com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.i) this.receiver).j.h(com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.k.a);
                break;
            case 10:
                ((com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.i) this.receiver).j.h(iVar);
                break;
            case 11:
                H h = (H) this.receiver;
                Intrinsics.checkNotNullParameter(h, "<this>");
                h.c("learn_settings_grading", new com.quizlet.quizletandroid.ui.login.z(14));
                break;
            case 12:
                com.quizlet.quizletandroid.ui.navigationmanagers.c cVar = (com.quizlet.quizletandroid.ui.navigationmanagers.c) this.receiver;
                cVar.getClass();
                com.quizlet.quizletandroid.ui.webpages.a.a.b(cVar.a, "https://www.surveymonkey.com/r/N7R76CQ", null);
                break;
            case 13:
                MatchEndGameFragment matchEndGameFragment = (MatchEndGameFragment) this.receiver;
                String str = MatchEndGameFragment.p;
                matchEndGameFragment.V().l.n();
                break;
            case 14:
                MatchEndGameFragment matchEndGameFragment2 = (MatchEndGameFragment) this.receiver;
                String str2 = MatchEndGameFragment.p;
                QProgressBar matchProgressBar = ((com.quizlet.quizletandroid.databinding.B) matchEndGameFragment2.J()).k;
                Intrinsics.checkNotNullExpressionValue(matchProgressBar, "matchProgressBar");
                matchProgressBar.setVisibility(0);
                matchEndGameFragment2.T().setVisibility(8);
                break;
            case 15:
                MatchGameFragment matchGameFragment = (MatchGameFragment) this.receiver;
                String str3 = MatchGameFragment.m;
                matchGameFragment.T().l.n();
                break;
            case 16:
                MatchStartGameFragment matchStartGameFragment = (MatchStartGameFragment) this.receiver;
                String str4 = MatchStartGameFragment.n;
                matchStartGameFragment.T().l.n();
                break;
            case 17:
                com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.a aVar = (com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.a) this.receiver;
                assistantMode.refactored.a.p(((com.quizlet.features.match.highscore.b) aVar.i.f).b, "PREF_SHOWN_NEW_TOOL_TIP", true);
                aVar.m.j(X.a);
                break;
            case 18:
                com.quizlet.quizletandroid.ui.studymodes.testmode.start.A a = (com.quizlet.quizletandroid.ui.studymodes.testmode.start.A) ((InterfaceC4758b) this.receiver);
                a.getClass();
                E.A(p0.j(a), null, null, new com.quizlet.quizletandroid.ui.studymodes.testmode.start.z(a, null), 3);
                break;
            case 19:
                com.quizlet.quizletandroid.ui.studymodes.testmode.start.A a2 = (com.quizlet.quizletandroid.ui.studymodes.testmode.start.A) ((InterfaceC4758b) this.receiver);
                a2.getClass();
                E.A(p0.j(a2), null, null, new com.quizlet.quizletandroid.ui.studymodes.testmode.start.x(a2, null), 3);
                break;
            case 20:
                ((SubjectCategoryActivity) this.receiver).onBackPressed();
                break;
            case 21:
                com.quizlet.quizletandroid.ui.subject.viewmodel.m mVar = (com.quizlet.quizletandroid.ui.subject.viewmodel.m) this.receiver;
                mVar.D();
                EventLoggerExt.c((EventLogger) mVar.e.b, new com.quizlet.features.practicetest.navigation.a(28));
                mVar.g.j(com.quizlet.quizletandroid.ui.subject.viewmodel.a.a);
                break;
            case EventType.WINDOW_STATE /* 22 */:
                com.quizlet.quizletandroid.ui.subject.viewmodel.m mVar2 = (com.quizlet.quizletandroid.ui.subject.viewmodel.m) this.receiver;
                mVar2.D();
                EventLoggerExt.c((EventLogger) mVar2.e.b, new com.quizlet.features.practicetest.navigation.a(29));
                E.A(p0.j(mVar2), null, null, new com.quizlet.quizletandroid.ui.subject.viewmodel.k(mVar2, null), 3);
                break;
            case EventType.AUDIO /* 23 */:
                com.quizlet.search.viewmodels.p pVar = (com.quizlet.search.viewmodels.p) this.receiver;
                pVar.B(pVar.n, true);
                com.quizlet.search.logging.b bVar = pVar.c;
                if (bVar.b.b.length() != 0) {
                    bVar.a.l(SearchEventsEventLog.Companion.a(SearchEventsEventLog.b, bVar.b.a, EnumC4466a1.TYPEAHEAD_CLICKED_VIEW_ALL_RESULTS.a(), bVar.b.b, null, null, null, null, null, null, null, null, null, null, 16376));
                }
                break;
            case EventType.VIDEO /* 24 */:
                com.quizlet.search.viewmodels.p pVar2 = (com.quizlet.search.viewmodels.p) this.receiver;
                pVar2.e.a.x("quizlet_live_did_tap_play_button");
                com.quizlet.search.viewmodels.p.A(pVar2, 3);
                break;
            case EventType.SUBS /* 25 */:
                com.quizlet.search.viewmodels.p pVar3 = (com.quizlet.search.viewmodels.p) this.receiver;
                pVar3.getClass();
                E.A(p0.j(pVar3), null, null, new C4805k(pVar3, null), 3);
                break;
            case EventType.CDN /* 26 */:
                com.quizlet.search.viewmodels.p pVar4 = (com.quizlet.search.viewmodels.p) this.receiver;
                SearchEventLogger searchEventLogger = pVar4.f;
                searchEventLogger.y();
                searchEventLogger.setQueryAndResetData("");
                do {
                    s0Var = pVar4.i;
                    value = s0Var.getValue();
                } while (!s0Var.k(value, com.quizlet.search.data.e.a));
            case 27:
                M m = (M) this.receiver;
                m.getClass();
                E.A(p0.j(m), null, null, new K(m, null), 3);
                break;
            case 28:
                ((com.quizlet.security.challenge.viewmodel.d) this.receiver).h.h(com.quizlet.security.challenge.viewmodel.b.a);
                break;
            default:
                ((com.quizlet.security.challenge.viewmodel.d) this.receiver).B();
                break;
        }
        return Unit.a;
    }
}
