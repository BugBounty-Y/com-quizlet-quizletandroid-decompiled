package com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4759a {
    public final List a;

    public C4759a(List item) {
        Intrinsics.checkNotNullParameter(item, "item");
        this.a = item;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4759a) && Intrinsics.b(this.a, ((C4759a) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("MotivationalMessageState(item="), this.a);
    }
}
