package com.quizlet.features.infra.folder.create.data;

import com.quizlet.data.model.AbstractC4119d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends g {
    public final AbstractC4119d0 a;

    public f(AbstractC4119d0 folder) {
        Intrinsics.checkNotNullParameter(folder, "folder");
        this.a = folder;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof f) && Intrinsics.b(this.a, ((f) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Success(folder=" + this.a + ")";
    }
}
