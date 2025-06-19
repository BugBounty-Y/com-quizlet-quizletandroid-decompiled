package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class j extends l {
    public final List a;

    public j(List list) {
        Intrinsics.checkNotNullParameter(list, "list");
        this.a = list;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof j) && Intrinsics.b(this.a, ((j) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("Loaded(list="), this.a);
    }
}
