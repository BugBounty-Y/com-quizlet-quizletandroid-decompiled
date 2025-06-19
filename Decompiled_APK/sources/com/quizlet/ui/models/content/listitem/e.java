package com.quizlet.ui.models.content.listitem;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e {
    public final long a;
    public final String b;

    public e(long j, String title) {
        Intrinsics.checkNotNullParameter(title, "title");
        this.a = j;
        this.b = title;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return this.a == eVar.a && Intrinsics.b(this.b, eVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FolderContentMetadata(id=");
        sb.append(this.a);
        sb.append(", title=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
