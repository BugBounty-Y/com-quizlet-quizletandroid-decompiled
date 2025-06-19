package com.quizlet.quizletandroid.ui.base;

import com.quizlet.db.data.models.wrappers.LoggedInUserStatus;
import kotlin.jvm.internal.B;

/* loaded from: classes3.dex */
public final /* synthetic */ class d extends B {
    public static final d a = new d(LoggedInUserStatus.class, "isLoggedIn", "isLoggedIn()Z", 0);

    @Override // kotlin.jvm.internal.B, kotlin.reflect.l
    public final Object get(Object obj) {
        return Boolean.valueOf(((LoggedInUserStatus) obj).isLoggedIn());
    }
}
