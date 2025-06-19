package com.quizlet.features.setpage.studypreview;

import androidx.compose.ui.node.B;
import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3567z;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.eventlogger.features.basequestion.QuestionEventLogData;
import com.quizlet.eventlogger.features.basequestion.QuestionEventLogger;
import com.quizlet.eventlogger.features.basequestion.QuestionEventSideData;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import com.quizlet.eventlogger.features.setpage.SetPagePerformanceLogger;
import com.quizlet.eventlogger.features.study.StudySessionQuestionEventLogger;
import com.quizlet.eventlogger.features.studymodes.StudyModeEventLogger;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.G1;
import com.quizlet.generated.enums.O1;
import java.util.UUID;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.Y;
import kotlinx.coroutines.flow.Z;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class g extends w0 {
    public final SearchEventLogger b;
    public final SetPagePerformanceLogger c;
    public final com.quizlet.features.setpage.studypreview.data.f d;
    public final com.quizlet.infra.legacysyncengine.net.f e;
    public final com.quizlet.time.b f;
    public final long g;
    public final s0 h;
    public final Z i;
    public final s0 j;
    public final Z k;
    public final d0 l;
    public final Y m;
    public Object n;
    public int o;
    public String p;
    public final String q;
    public final long r;
    public Long s;
    public final long t;
    public boolean u;
    public boolean v;
    public final StudyModeEventLogger w;
    public final StudySessionQuestionEventLogger x;

    public g(m0 savedStateHandle, StudyModeEventLogger.Factory studyModeLoggerFactory, StudySessionQuestionEventLogger.Factory studySessionQuestionEventLoggerFactory, SearchEventLogger searchEventLogger, SetPagePerformanceLogger setPagePerformanceLogger, com.quizlet.features.setpage.studypreview.data.f studyPreviewOnboardingState, com.quizlet.infra.legacysyncengine.net.f syncDispatcher, long j) {
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(studyModeLoggerFactory, "studyModeLoggerFactory");
        Intrinsics.checkNotNullParameter(studySessionQuestionEventLoggerFactory, "studySessionQuestionEventLoggerFactory");
        Intrinsics.checkNotNullParameter(searchEventLogger, "searchEventLogger");
        Intrinsics.checkNotNullParameter(setPagePerformanceLogger, "setPagePerformanceLogger");
        Intrinsics.checkNotNullParameter(studyPreviewOnboardingState, "studyPreviewOnboardingState");
        Intrinsics.checkNotNullParameter(syncDispatcher, "syncDispatcher");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        this.b = searchEventLogger;
        this.c = setPagePerformanceLogger;
        this.d = studyPreviewOnboardingState;
        this.e = syncDispatcher;
        this.f = timeProvider;
        this.g = j;
        s0 s0VarC = e0.c(com.quizlet.features.setpage.studypreview.data.c.a);
        this.h = s0VarC;
        this.i = new Z(s0VarC);
        s0 s0VarC2 = e0.c(Boolean.FALSE);
        this.j = s0VarC2;
        this.k = new Z(s0VarC2);
        d0 d0VarB = e0.b(0, 0, null, 7);
        this.l = d0VarB;
        this.m = new Y(d0VarB);
        this.n = K.a;
        this.o = -1;
        this.p = B.f("toString(...)");
        String strF = B.f("toString(...)");
        this.q = strF;
        Long l = (Long) savedStateHandle.a("setId");
        this.r = l != null ? l.longValue() : 0L;
        this.t = System.currentTimeMillis();
        StudyModeEventLogger studyModeEventLoggerA = studyModeLoggerFactory.a(A1.FLASHCARDS);
        Intrinsics.checkNotNullExpressionValue(studyModeEventLoggerA, "create(...)");
        this.w = studyModeEventLoggerA;
        StudySessionQuestionEventLogger studySessionQuestionEventLoggerA = studySessionQuestionEventLoggerFactory.a();
        this.x = studySessionQuestionEventLoggerA;
        studySessionQuestionEventLoggerA.b(strF);
    }

    public static QuestionEventLogData A(com.quizlet.features.setpage.studypreview.data.a aVar) {
        return new QuestionEventLogData(Long.valueOf(aVar.a), aVar.b, new QuestionEventSideData(O1.WORD, true, false, false), new QuestionEventSideData(O1.DEFINITION, aVar.d.a != null, aVar.e != null, false), "");
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r1v0, types: [java.lang.Object, java.util.List] */
    public final void B() {
        int i = this.o;
        if (i < 0 || i >= this.n.size()) {
            return;
        }
        com.quizlet.features.setpage.studypreview.data.a aVar = (com.quizlet.features.setpage.studypreview.data.a) this.n.get(this.o);
        QuestionEventLogger.DefaultImpls.a(this.x, this.p, "view_end", A(aVar), 0, null, null, null, null, null, null, 1920);
    }

    /* JADX WARN: Type inference failed for: r0v12, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r0v15, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r0v9, types: [java.lang.Object, java.util.List] */
    public final void C(AbstractC3567z event) {
        Intrinsics.checkNotNullParameter(event, "event");
        if (event instanceof h) {
            if (((h) event).a) {
                this.b.l(this.q);
                return;
            }
            return;
        }
        if (!(event instanceof j)) {
            if (event instanceof i) {
                QuestionEventLogger.DefaultImpls.a(this.x, this.p, "reveal", A(((i) event).a), 0, null, null, null, null, null, null, 1920);
                return;
            } else if (event instanceof m) {
                E.A(p0.j(this), null, null, new e(this, ((m) event).a, null), 3);
                return;
            } else if (event instanceof l) {
                this.c.f();
                return;
            } else {
                if (!(event instanceof k)) {
                    throw new NoWhenBranchMatchedException();
                }
                E.A(p0.j(this), null, null, new f(this, null), 3);
                return;
            }
        }
        int size = this.n.size();
        int i = ((j) event).a;
        if (i >= size || i == this.o) {
            return;
        }
        B();
        this.o = i;
        com.quizlet.features.setpage.studypreview.data.a aVar = (com.quizlet.features.setpage.studypreview.data.a) this.n.get(i);
        String string = UUID.randomUUID().toString();
        this.p = string;
        QuestionEventLogger.DefaultImpls.a(this.x, string, "view_start", A(aVar), 0, null, null, null, null, null, assistantMode.enums.k.j, 896);
        if (i != this.n.size() - 1 || this.u) {
            return;
        }
        this.u = true;
        DBSession dBSession = new DBSession(this.g, this.r, G1.SET, A1.FLASHCARDS, this.v, this.t);
        this.f.getClass();
        dBSession.setEndedTimestampMs(System.currentTimeMillis());
        this.e.a(dBSession);
    }

    @Override // androidx.lifecycle.w0
    public final void z() {
        B();
        if (this.s != null) {
            this.w.d(this.q, G1.SET, 1, null, Long.valueOf(this.r), this.s, false, "results");
        }
    }
}
