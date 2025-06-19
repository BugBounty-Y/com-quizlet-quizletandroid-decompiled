package com.quizlet.ui.models.content.listitem;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g {
    public final String a;
    public final String b;

    public g(String uuid, String title) {
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        Intrinsics.checkNotNullParameter(title, "title");
        this.a = uuid;
        this.b = title;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return Intrinsics.b(this.a, gVar.a) && Intrinsics.b(this.b, gVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PracticeTestContentMetadata(uuid=");
        sb.append(this.a);
        sb.append(", title=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
