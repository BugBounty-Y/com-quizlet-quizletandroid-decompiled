package com.quizlet.eventlogger.events;

import com.quizlet.db.data.models.persisted.DBUser;

/* loaded from: classes2.dex */
public class CurrentUserEvent {
    public final DBUser a;
    public final long b;
    public final boolean c;

    public CurrentUserEvent(DBUser dBUser, long j) {
        this.a = dBUser;
        this.b = j;
        this.c = j > 0;
    }

    public DBUser getCurrentUser() {
        return this.a;
    }

    public long getCurrentUserId() {
        return this.b;
    }
}
