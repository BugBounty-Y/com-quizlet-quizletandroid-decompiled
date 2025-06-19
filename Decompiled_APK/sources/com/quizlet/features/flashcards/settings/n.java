package com.quizlet.features.flashcards.settings;

import androidx.appcompat.app.y;
import com.quizlet.quizletandroid.R;
import java.util.List;
import kotlin.collections.B;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class n extends y {
    public final boolean d;

    public n(boolean z) {
        super(Boolean.valueOf(z), B.j(Boolean.FALSE, Boolean.TRUE));
        this.d = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof n) && this.d == ((n) obj).d;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.d);
    }

    @Override // androidx.appcompat.app.y
    public final com.quizlet.qutils.string.g m(int i) {
        if (((Boolean) ((List) this.b).get(i)).booleanValue()) {
            Object[] args = new Object[0];
            Intrinsics.checkNotNullParameter(args, "args");
            return new com.quizlet.qutils.string.f(R.string.starred_only, C4933y.P(args));
        }
        Object[] args2 = new Object[0];
        Intrinsics.checkNotNullParameter(args2, "args");
        return new com.quizlet.qutils.string.f(R.string.starred_all, C4933y.P(args2));
    }

    @Override // androidx.appcompat.app.y
    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("SelectedCardsModeControlState(isSelectedMode="), this.d);
    }
}
