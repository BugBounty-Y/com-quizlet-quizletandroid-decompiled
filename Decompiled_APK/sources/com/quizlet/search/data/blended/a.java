package com.quizlet.search.data.blended;

import androidx.compose.animation.d0;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final List a;
    public final String b;
    public final List c;

    public a(String sessionId, List items, List orderShelfListLogData) {
        Intrinsics.checkNotNullParameter(items, "items");
        Intrinsics.checkNotNullParameter(sessionId, "sessionId");
        Intrinsics.checkNotNullParameter(orderShelfListLogData, "orderShelfListLogData");
        this.a = items;
        this.b = sessionId;
        this.c = orderShelfListLogData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b) && Intrinsics.b(this.c, aVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.e(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AllResultsDataUiWrapper(items=");
        sb.append(this.a);
        sb.append(", sessionId=");
        sb.append(this.b);
        sb.append(", orderShelfListLogData=");
        return android.support.v4.media.session.a.n(")", sb, this.c);
    }
}
