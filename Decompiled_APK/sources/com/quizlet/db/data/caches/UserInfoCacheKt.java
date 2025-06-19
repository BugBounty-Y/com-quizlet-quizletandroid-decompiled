package com.quizlet.db.data.caches;

import com.quizlet.db.data.models.persisted.DBUser;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class UserInfoCacheKt {
    public static final void a(UserInfoCache userInfoCache, DBUser dBUser) {
        Intrinsics.checkNotNullParameter(userInfoCache, "<this>");
        userInfoCache.c(dBUser != null ? dBUser.getId() : 0L, dBUser != null ? dBUser.getUsername() : null, dBUser != null ? dBUser.getImageUrl() : null, dBUser != null ? Integer.valueOf(dBUser.getCreatorBadgeText()) : null);
    }
}
