package com.quizlet.features.folders.changetags.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements e {
    public final com.quizlet.features.infra.folder.menu.data.f a;

    public d(com.quizlet.features.infra.folder.menu.data.f option) {
        Intrinsics.checkNotNullParameter(option, "option");
        this.a = option;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof d) && Intrinsics.b(this.a, ((d) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "SubfolderSelected(option=" + this.a + ")";
    }
}
