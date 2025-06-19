package com.quizlet.login.authentication.data;

import com.quizlet.db.data.models.persisted.DBUser;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class l extends i {
    public final String a;
    public final DBUser b;

    public l(String accessToken, DBUser user) {
        Intrinsics.checkNotNullParameter(accessToken, "accessToken");
        Intrinsics.checkNotNullParameter(user, "user");
        this.a = accessToken;
        this.b = user;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof l)) {
            return false;
        }
        l lVar = (l) obj;
        return Intrinsics.b(this.a, lVar.a) && Intrinsics.b(this.b, lVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "Success(accessToken=" + this.a + ", user=" + this.b + ")";
    }
}
