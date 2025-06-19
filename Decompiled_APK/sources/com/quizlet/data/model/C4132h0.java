package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.h0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4132h0 {
    public final AbstractC4119d0 a;
    public final User b;

    public C4132h0(AbstractC4119d0 folder, User user) {
        Intrinsics.checkNotNullParameter(folder, "folder");
        this.a = folder;
        this.b = user;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4132h0)) {
            return false;
        }
        C4132h0 c4132h0 = (C4132h0) obj;
        return Intrinsics.b(this.a, c4132h0.a) && Intrinsics.b(this.b, c4132h0.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        User user = this.b;
        return iHashCode + (user == null ? 0 : user.hashCode());
    }

    public final String toString() {
        return "FolderWithCreator(folder=" + this.a + ", creator=" + this.b + ")";
    }
}
