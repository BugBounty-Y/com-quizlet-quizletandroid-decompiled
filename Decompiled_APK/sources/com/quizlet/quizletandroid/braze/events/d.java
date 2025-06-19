package com.quizlet.quizletandroid.braze.events;

import androidx.compose.animation.core.J0;

/* loaded from: classes3.dex */
public final class d extends J0 {
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        ((d) obj).getClass();
        return true;
    }

    public final int hashCode() {
        return 1242223269;
    }

    @Override // androidx.compose.animation.core.J0
    public final String toString() {
        return "ViewAccountBrazeEvent(name=account_page_view_app)";
    }

    @Override // androidx.compose.animation.core.J0
    public final String z() {
        return "account_page_view_app";
    }
}
