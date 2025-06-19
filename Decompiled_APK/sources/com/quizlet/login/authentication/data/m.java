package com.quizlet.login.authentication.data;

import com.quizlet.db.data.models.persisted.DBUser;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m extends i {
    public final String a;
    public final DBUser b;

    public m(String accessToken, DBUser user) {
        Intrinsics.checkNotNullParameter(accessToken, "accessToken");
        Intrinsics.checkNotNullParameter(user, "user");
        this.a = accessToken;
        this.b = user;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof m)) {
            return false;
        }
        m mVar = (m) obj;
        return Intrinsics.b(this.a, mVar.a) && Intrinsics.b(this.b, mVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "SuccessWithUpsell(accessToken=" + this.a + ", user=" + this.b + ")";
    }
}
