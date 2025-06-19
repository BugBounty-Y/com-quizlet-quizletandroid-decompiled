package com.quizlet.remote.model.set;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e {
    public final com.quizlet.quizletandroid.ui.activitycenter.models.a a;
    public final com.quizlet.quizletandroid.ui.profile.data.b b;

    public e(com.quizlet.quizletandroid.ui.activitycenter.models.a userMapper, com.quizlet.quizletandroid.ui.profile.data.b setMapper, com.quizlet.remote.model.school.a schoolMapper, com.quizlet.remote.model.course.c courseMapper) {
        Intrinsics.checkNotNullParameter(userMapper, "userMapper");
        Intrinsics.checkNotNullParameter(setMapper, "setMapper");
        Intrinsics.checkNotNullParameter(schoolMapper, "schoolMapper");
        Intrinsics.checkNotNullParameter(courseMapper, "courseMapper");
        this.a = userMapper;
        this.b = setMapper;
    }
}
