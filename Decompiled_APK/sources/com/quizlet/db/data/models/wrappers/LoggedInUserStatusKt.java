package com.quizlet.db.data.models.wrappers;

import com.quizlet.db.data.models.persisted.DBUser;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class LoggedInUserStatusKt {
    public static final boolean isConfirmationRequired(@NotNull LoggedInUserStatus loggedInUserStatus) {
        Intrinsics.checkNotNullParameter(loggedInUserStatus, "<this>");
        DBUser currentUser = loggedInUserStatus.getCurrentUser();
        return currentUser != null && currentUser.isConfirmationRequired();
    }

    public static final boolean isFreeUser(@NotNull LoggedInUserStatus loggedInUserStatus) {
        Intrinsics.checkNotNullParameter(loggedInUserStatus, "<this>");
        DBUser currentUser = loggedInUserStatus.getCurrentUser();
        return currentUser != null && currentUser.getUserUpgradeType() == 0;
    }

    public static final boolean isUnderage(@NotNull LoggedInUserStatus loggedInUserStatus) {
        Intrinsics.checkNotNullParameter(loggedInUserStatus, "<this>");
        DBUser currentUser = loggedInUserStatus.getCurrentUser();
        return currentUser != null && currentUser.getIsUnderAge();
    }
}
