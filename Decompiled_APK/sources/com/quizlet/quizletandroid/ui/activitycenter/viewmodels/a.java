package com.quizlet.quizletandroid.ui.activitycenter.viewmodels;

import android.content.Context;
import androidx.lifecycle.X;
import com.quizlet.data.interactor.achievements.f;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.login.common.interactors.d;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.activitycenter.managers.ActivityCenterContentCardsUpdateHandler;
import com.quizlet.qutils.android.e;
import com.quizlet.viewmodel.b;
import java.util.ArrayList;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class a extends b {
    public final com.quizlet.data.repository.explanations.myexplanations.a c;
    public final f d;
    public final d e;
    public final ActivityCenterContentCardsUpdateHandler f;
    public final X g;
    public final X h;
    public final X i;
    public final ArrayList j;

    public a(com.quizlet.data.repository.explanations.myexplanations.a activityCenterLogger, f syncedActivityCenterManager, d refreshActivityCenterUseCase) {
        Intrinsics.checkNotNullParameter(activityCenterLogger, "activityCenterLogger");
        Intrinsics.checkNotNullParameter(syncedActivityCenterManager, "syncedActivityCenterManager");
        Intrinsics.checkNotNullParameter(refreshActivityCenterUseCase, "refreshActivityCenterUseCase");
        this.c = activityCenterLogger;
        this.d = syncedActivityCenterManager;
        this.e = refreshActivityCenterUseCase;
        ActivityCenterContentCardsUpdateHandler activityCenterContentCardsUpdateHandler = new ActivityCenterContentCardsUpdateHandler();
        this.f = activityCenterContentCardsUpdateHandler;
        this.g = new X(1);
        this.h = new X(1);
        this.i = new X(1);
        this.j = new ArrayList();
        com.quizlet.login.common.navigation.d onHandle = new com.quizlet.login.common.navigation.d(1, this, a.class, "handleCardUpdate", "handleCardUpdate(Lcom/braze/events/ContentCardsUpdatedEvent;)Ljava/util/List;", 0, 15);
        Intrinsics.checkNotNullParameter(onHandle, "onHandle");
        activityCenterContentCardsUpdateHandler.a = onHandle;
        com.quizlet.quizletandroid.ui.common.images.capture.b bVar = e.a;
        Context context = (Context) activityCenterLogger.b;
        bVar.getClass();
        boolean zJ = com.quizlet.quizletandroid.ui.common.images.capture.b.j(context);
        String string = context.getString(R.string.loggingTag_ActivityCenter);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        ((EventLogger) activityCenterLogger.c).B(string, zJ);
    }
}
