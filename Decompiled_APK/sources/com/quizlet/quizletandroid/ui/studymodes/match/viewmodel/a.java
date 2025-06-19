package com.quizlet.quizletandroid.ui.studymodes.match.viewmodel;

import androidx.compose.foundation.text.input.internal.u;
import androidx.compose.ui.node.V;
import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import androidx.lifecycle.m0;
import com.google.android.datatransport.cct.internal.s;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.data.repository.metering.j;
import io.reactivex.rxjava3.subjects.r;
import java.text.DecimalFormat;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class a extends com.quizlet.viewmodel.b {
    public final com.quizlet.infra.legacysyncengine.managers.d c;
    public final androidx.work.impl.model.c d;
    public final com.quizlet.features.match.highscore.b e;
    public final com.quizlet.features.infra.basestudy.manager.f f;
    public final com.quizlet.features.match.logging.b g;
    public final j h;
    public final s i;
    public final com.quizlet.quizletandroid.ui.studymodes.match.managers.a j;
    public final com.quizlet.viewmodel.livedata.b k;
    public final com.quizlet.viewmodel.livedata.b l;
    public final Y m;
    public final X n;
    public final DecimalFormat o;
    public boolean p;
    public final r q;

    public a(m0 savedStateHandle, com.quizlet.features.infra.basestudy.manager.a studyModeManagerFactory, u dataProviderFactory, V highScoresDataManagerFactory, com.quizlet.data.repository.studysetwithcreator.d matchShareSetManagerFactory, com.quizlet.data.repository.course.membership.c matchStudyModeLoggerFactor, com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager, androidx.work.impl.model.c userProperties, com.quizlet.features.match.highscore.b highScoresState) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(studyModeManagerFactory, "studyModeManagerFactory");
        Intrinsics.checkNotNullParameter(dataProviderFactory, "dataProviderFactory");
        Intrinsics.checkNotNullParameter(highScoresDataManagerFactory, "highScoresDataManagerFactory");
        Intrinsics.checkNotNullParameter(matchShareSetManagerFactory, "matchShareSetManagerFactory");
        Intrinsics.checkNotNullParameter(matchStudyModeLoggerFactor, "matchStudyModeLoggerFactor");
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(highScoresState, "highScoresState");
        this.c = loggedInUserManager;
        this.d = userProperties;
        this.e = highScoresState;
        this.f = studyModeManagerFactory.a(savedStateHandle);
        this.g = matchStudyModeLoggerFactor.f(savedStateHandle);
        this.h = dataProviderFactory.d(savedStateHandle);
        this.i = highScoresDataManagerFactory.c(savedStateHandle);
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        s sVarC = ((V) matchShareSetManagerFactory.c).c(savedStateHandle);
        this.j = new com.quizlet.quizletandroid.ui.studymodes.match.managers.a(((com.quizlet.features.infra.basestudy.manager.a) matchShareSetManagerFactory.d).a(savedStateHandle), (com.quizlet.infra.legacysyncengine.managers.d) matchShareSetManagerFactory.a, sVarC, (com.quizlet.quizletandroid.deeplinks.a) matchShareSetManagerFactory.b);
        com.quizlet.viewmodel.livedata.b bVar = new com.quizlet.viewmodel.livedata.b();
        this.k = bVar;
        com.quizlet.viewmodel.livedata.b bVar2 = new com.quizlet.viewmodel.livedata.b();
        this.l = bVar2;
        Y y = new Y();
        this.m = y;
        this.n = new X(1);
        this.o = new DecimalFormat("0.0");
        this.q = Z.f("create(...)");
        bVar.n();
        bVar2.n();
        y.j(com.quizlet.features.match.data.X.a);
    }
}
