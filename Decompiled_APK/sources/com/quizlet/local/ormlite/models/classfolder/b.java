package com.quizlet.local.ormlite.models.classfolder;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final List a;
    public final List b;

    public b(List folderIds, List classIds) {
        Intrinsics.checkNotNullParameter(folderIds, "folderIds");
        Intrinsics.checkNotNullParameter(classIds, "classIds");
        this.a = folderIds;
        this.b = classIds;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && Intrinsics.b(this.b, bVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("IdsForCreation(folderIds=");
        sb.append(this.a);
        sb.append(", classIds=");
        return android.support.v4.media.session.a.n(")", sb, this.b);
    }
}
