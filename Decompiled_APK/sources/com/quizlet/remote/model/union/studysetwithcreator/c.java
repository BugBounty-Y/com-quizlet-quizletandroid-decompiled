package com.quizlet.remote.model.union.studysetwithcreator;

import com.quizlet.quizletandroid.ui.joincontenttofolder.j;
import com.quizlet.quizletandroid.ui.profile.p;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public final com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c a;

    public c(com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c dataSource, com.quizlet.quizletandroid.ui.activitycenter.models.a userMapper, com.quizlet.quizletandroid.ui.profile.data.b setMapper, com.quizlet.quizletandroid.ui.folder.logging.a pagingKeyMapper, p classificationMapper, j remoteSocialSignalsMapper) {
        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
        Intrinsics.checkNotNullParameter(userMapper, "userMapper");
        Intrinsics.checkNotNullParameter(setMapper, "setMapper");
        Intrinsics.checkNotNullParameter(pagingKeyMapper, "pagingKeyMapper");
        Intrinsics.checkNotNullParameter(classificationMapper, "classificationMapper");
        Intrinsics.checkNotNullParameter(remoteSocialSignalsMapper, "remoteSocialSignalsMapper");
        this.a = dataSource;
    }
}
