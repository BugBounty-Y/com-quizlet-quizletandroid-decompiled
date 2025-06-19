package com.quizlet.quizletandroid.ui.studymodes.match.managers;

import com.google.android.datatransport.cct.internal.s;
import com.quizlet.features.infra.basestudy.manager.f;
import com.quizlet.infra.legacysyncengine.managers.d;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final f a;
    public final d b;
    public final s c;

    public a(f studyModeManager, d loggedInUserManager, s matchHighScoresDataManager, com.quizlet.quizletandroid.deeplinks.a setPageDeepLinkLookup) {
        Intrinsics.checkNotNullParameter(studyModeManager, "studyModeManager");
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(matchHighScoresDataManager, "matchHighScoresDataManager");
        Intrinsics.checkNotNullParameter(setPageDeepLinkLookup, "setPageDeepLinkLookup");
        this.a = studyModeManager;
        this.b = loggedInUserManager;
        this.c = matchHighScoresDataManager;
    }
}
