package com.quizlet.search.data.newsearch.user;

import com.quizlet.data.model.User;
import com.quizlet.search.data.newsearch.e;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements e {
    public final User a;

    public a(User data) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.a = data;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof a) && Intrinsics.b(this.a, ((a) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "NewSearchUser(data=" + this.a + ")";
    }
}
