package com.quizlet.quizletandroid.ui;

import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.wrappers.LoggedInUserStatus;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.functions.i;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements i, h {
    public static final c a = new c();
    public static final c b = new c();

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        LoggedInUserStatus it2 = (LoggedInUserStatus) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        DBUser currentUser = it2.getCurrentUser();
        Intrinsics.d(currentUser);
        return currentUser;
    }

    @Override // io.reactivex.rxjava3.functions.i
    public boolean test(Object obj) {
        LoggedInUserStatus it2 = (LoggedInUserStatus) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        return it2.isLoggedIn() && it2.getCurrentUser() != null;
    }
}
