package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class CreatedFolderWithCreator {
    public final CreatedFolder a;
    public final User b;

    public CreatedFolderWithCreator(CreatedFolder folder, User user) {
        Intrinsics.checkNotNullParameter(folder, "folder");
        this.a = folder;
        this.b = user;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof CreatedFolderWithCreator)) {
            return false;
        }
        CreatedFolderWithCreator createdFolderWithCreator = (CreatedFolderWithCreator) obj;
        return Intrinsics.b(this.a, createdFolderWithCreator.a) && Intrinsics.b(this.b, createdFolderWithCreator.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        User user = this.b;
        return iHashCode + (user == null ? 0 : user.hashCode());
    }

    public final String toString() {
        return "CreatedFolderWithCreator(folder=" + this.a + ", creator=" + this.b + ")";
    }
}
