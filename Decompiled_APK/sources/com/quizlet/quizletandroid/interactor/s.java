package com.quizlet.quizletandroid.interactor;

import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.wrappers.LoggedInUserStatus;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class s implements io.reactivex.rxjava3.functions.h {
    public static final s b = new s();
    public final /* synthetic */ int a = 0;

    public /* synthetic */ s() {
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        switch (this.a) {
            case 0:
                LoggedInUserStatus it2 = (LoggedInUserStatus) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return com.google.android.gms.common.wrappers.a.d(it2.getCurrentUser());
            default:
                DBUser p0 = (DBUser) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                return retrofit2.adapter.rxjava3.d.s(p0);
        }
    }

    public s(retrofit2.adapter.rxjava3.d dVar) {
    }
}
