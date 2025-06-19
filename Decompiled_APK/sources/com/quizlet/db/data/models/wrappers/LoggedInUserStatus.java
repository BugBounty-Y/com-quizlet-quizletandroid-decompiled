package com.quizlet.db.data.models.wrappers;

import com.quizlet.db.data.models.persisted.DBUser;
import kotlin.Metadata;

@Metadata
/* loaded from: classes2.dex */
public final class LoggedInUserStatus {
    private final DBUser currentUser;
    private final long personId;

    public LoggedInUserStatus(long j, DBUser dBUser) {
        this.personId = j;
        this.currentUser = dBUser;
    }

    public final DBUser getCurrentUser() {
        return this.currentUser;
    }

    public final long getPersonId() {
        return this.personId;
    }

    public final boolean isLoggedIn() {
        return this.currentUser != null;
    }
}
