package com.quizlet.features.match.viewmodel;

import androidx.lifecycle.X;
import androidx.lifecycle.m0;
import com.quizlet.features.match.data.C4361q;
import com.quizlet.features.match.data.C4362s;
import com.quizlet.features.match.data.C4365v;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class f extends com.quizlet.viewmodel.b {
    public final com.quizlet.features.match.studyengine.g c;
    public final com.quizlet.viewmodel.livedata.b d;
    public final X e;
    public boolean f;
    public boolean g;

    public f(m0 savedStateHandle, com.quizlet.features.match.studyengine.f gameManagerFactory, com.quizlet.data.repository.course.membership.c matchStudyModeLoggerFactory) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(gameManagerFactory, "gameManagerFactory");
        Intrinsics.checkNotNullParameter(matchStudyModeLoggerFactory, "matchStudyModeLoggerFactory");
        com.quizlet.features.match.logging.b bVarF = matchStudyModeLoggerFactory.f(savedStateHandle);
        this.c = gameManagerFactory.a(savedStateHandle);
        com.quizlet.viewmodel.livedata.b bVar = new com.quizlet.viewmodel.livedata.b();
        this.d = bVar;
        this.e = new X(1);
        bVar.n();
        bVarF.c.I("match_game_start");
    }

    public final void B() {
        if (!this.f) {
            timber.log.c.a.o("Trying to start a game that hasn't been created yet", new Object[0]);
            this.d.o(C4365v.a);
        } else {
            com.quizlet.features.match.studyengine.e eVar = (com.quizlet.features.match.studyengine.e) this.c;
            eVar.b();
            long jCurrentTimeMillis = System.currentTimeMillis();
            eVar.f = jCurrentTimeMillis;
            this.e.l(new C4362s(jCurrentTimeMillis));
        }
    }

    public final void C() {
        com.quizlet.features.match.studyengine.e eVar = (com.quizlet.features.match.studyengine.e) this.c;
        eVar.b();
        long j = eVar.h + 1000;
        eVar.h = j;
        this.e.l(new C4361q(j));
    }
}
