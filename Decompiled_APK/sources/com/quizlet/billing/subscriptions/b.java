package com.quizlet.billing.subscriptions;

import com.quizlet.db.data.models.persisted.DBUser;

/* loaded from: classes2.dex */
public final class b {
    public final DBUser a;
    public final Throwable b;

    public b(Throwable th) {
        this.b = th;
        this.a = null;
    }

    public b(DBUser dBUser) {
        this.a = dBUser;
        this.b = null;
    }
}
