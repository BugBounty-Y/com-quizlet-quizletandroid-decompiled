package com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4763e extends AbstractC4766h {
    public final List a;

    public C4763e(List missedTermIds) {
        Intrinsics.checkNotNullParameter(missedTermIds, "missedTermIds");
        this.a = missedTermIds;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4763e) && Intrinsics.b(this.a, ((C4763e) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("GoToLearn(missedTermIds="), this.a);
    }
}
