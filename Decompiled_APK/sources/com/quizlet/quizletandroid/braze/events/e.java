package com.quizlet.quizletandroid.braze.events;

import androidx.compose.animation.core.J0;

/* loaded from: classes3.dex */
public final class e extends J0 {
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        ((e) obj).getClass();
        return true;
    }

    public final int hashCode() {
        return 910878806;
    }

    @Override // androidx.compose.animation.core.J0
    public final String toString() {
        return "ViewHomeBrazeEvent(name=homepage_view)";
    }

    @Override // androidx.compose.animation.core.J0
    public final String z() {
        return "homepage_view";
    }
}
