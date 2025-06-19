package com.quizlet.quizletandroid.ui.base;

import com.quizlet.db.data.models.wrappers.LoggedInUserStatus;
import kotlin.jvm.internal.B;

/* loaded from: classes3.dex */
public final /* synthetic */ class f extends B {
    public static final f a = new f(LoggedInUserStatus.class, "personId", "getPersonId()J", 0);

    @Override // kotlin.jvm.internal.B, kotlin.reflect.l
    public final Object get(Object obj) {
        return Long.valueOf(((LoggedInUserStatus) obj).getPersonId());
    }
}
