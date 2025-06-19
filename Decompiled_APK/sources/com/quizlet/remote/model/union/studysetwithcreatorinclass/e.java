package com.quizlet.remote.model.union.studysetwithcreatorinclass;

import com.quizlet.quizletandroid.ui.joincontenttofolder.j;
import com.quizlet.quizletandroid.ui.login.h;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;

/* loaded from: classes3.dex */
public final class e {
    public final h a;
    public final j b;
    public final com.quizlet.quizletandroid.ui.activitycenter.models.a c;
    public final AbstractC5040y d;

    public e(h dataSource, j classSetMapper, com.quizlet.quizletandroid.ui.profile.data.b studySetMapper, com.quizlet.quizletandroid.ui.activitycenter.models.a userMapper, AbstractC5040y ioDispatcher) {
        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
        Intrinsics.checkNotNullParameter(classSetMapper, "classSetMapper");
        Intrinsics.checkNotNullParameter(studySetMapper, "studySetMapper");
        Intrinsics.checkNotNullParameter(userMapper, "userMapper");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.a = dataSource;
        this.b = classSetMapper;
        this.c = userMapper;
        this.d = ioDispatcher;
    }
}
