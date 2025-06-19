package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class H {
    public final ContentFolder a;
    public final User b;

    public H(ContentFolder folder, User user) {
        Intrinsics.checkNotNullParameter(folder, "folder");
        this.a = folder;
        this.b = user;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof H)) {
            return false;
        }
        H h = (H) obj;
        return Intrinsics.b(this.a, h.a) && Intrinsics.b(this.b, h.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        User user = this.b;
        return iHashCode + (user == null ? 0 : user.hashCode());
    }

    public final String toString() {
        return "ContentFoldersWithCreator(folder=" + this.a + ", creator=" + this.b + ")";
    }
}
