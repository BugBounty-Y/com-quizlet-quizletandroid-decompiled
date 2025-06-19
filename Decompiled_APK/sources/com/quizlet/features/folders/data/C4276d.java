package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.data.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4276d implements T {
    public final String a;

    public C4276d(String clickSource) {
        Intrinsics.checkNotNullParameter(clickSource, "clickSource");
        this.a = clickSource;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4276d) && Intrinsics.b(this.a, ((C4276d) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("AddToFolderClicked(clickSource="), this.a, ")");
    }
}
