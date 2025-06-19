package com.quizlet.data.repository.user;

import java.util.UUID;

/* loaded from: classes2.dex */
public interface b {
    UUID getDeviceId();

    boolean getHasLoggedInBefore();

    long getPersonId();

    String getProfileImage();

    int getUserBadgeStringResId();

    String getUsername();
}
