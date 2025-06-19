package com.quizlet.quizletandroid.ui.startpage.nav2.screenstates;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class v {
    public final List a;

    public v(List orderList) {
        Intrinsics.checkNotNullParameter(orderList, "orderList");
        this.a = orderList;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof v) && Intrinsics.b(this.a, ((v) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("SetAdapterOrder(orderList="), this.a);
    }
}
