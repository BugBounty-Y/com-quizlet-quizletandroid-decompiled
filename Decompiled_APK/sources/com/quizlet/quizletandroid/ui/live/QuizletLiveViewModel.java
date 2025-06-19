package com.quizlet.quizletandroid.ui.live;

import android.webkit.JavascriptInterface;
import androidx.annotation.Keep;
import androidx.compose.animation.d0;
import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import androidx.lifecycle.w0;
import com.quizlet.infra.legacysyncengine.managers.g;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class QuizletLiveViewModel extends w0 {
    public final com.quizlet.features.emailconfirmation.logging.a b;
    public final g c;
    public final com.quizlet.infra.legacysyncengine.managers.d d;
    public final X e;
    public final JsBridge f;
    public final Y g;
    public com.quizlet.infra.legacysyncengine.managers.f h;

    @Metadata
    public final class JsBridge {
        public JsBridge() {
        }

        @JavascriptInterface
        @Keep
        public final void onJoinGame(String str) {
            QuizletLiveViewModel quizletLiveViewModel = QuizletLiveViewModel.this;
            quizletLiveViewModel.e.j(Boolean.TRUE);
            com.quizlet.infra.legacysyncengine.managers.f fVar = quizletLiveViewModel.h;
            if (fVar == null) {
                Intrinsics.m("joinMethod");
                throw null;
            }
            int iOrdinal = fVar.ordinal();
            com.quizlet.features.emailconfirmation.logging.a aVar = quizletLiveViewModel.b;
            if (iOrdinal == 0) {
                aVar.a.x("quizlet_live_join_game_with_game_code");
            } else {
                if (iOrdinal != 1) {
                    throw new NoWhenBranchMatchedException();
                }
                aVar.a.x("quizlet_live_join_game_with_qr_code");
            }
            com.quizlet.infra.legacysyncengine.managers.f joinMethod = quizletLiveViewModel.h;
            if (joinMethod == null) {
                Intrinsics.m("joinMethod");
                throw null;
            }
            long personId = quizletLiveViewModel.d.e.getPersonId();
            g gVar = quizletLiveViewModel.c;
            gVar.getClass();
            Intrinsics.checkNotNullParameter(joinMethod, "joinMethod");
            gVar.a.edit().putInt(d0.s(new Object[]{Long.valueOf(personId)}, 1, "user_preferred_join_method_%s", "format(...)"), joinMethod.a).apply();
        }
    }

    public QuizletLiveViewModel(com.quizlet.features.emailconfirmation.logging.a quizletLiveLogger, g livePreferencesManager, com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager) {
        Intrinsics.checkNotNullParameter(quizletLiveLogger, "quizletLiveLogger");
        Intrinsics.checkNotNullParameter(livePreferencesManager, "livePreferencesManager");
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        this.b = quizletLiveLogger;
        this.c = livePreferencesManager;
        this.d = loggedInUserManager;
        this.e = new X(1);
        this.f = new JsBridge();
        Y y = new Y();
        this.g = y;
        y.j(Unit.a);
    }
}
