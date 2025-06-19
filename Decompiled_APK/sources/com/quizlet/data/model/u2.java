package com.quizlet.data.model;

/* loaded from: classes2.dex */
public final class u2 {
    public final int a;
    public final boolean b;

    public u2(int i) {
        this.a = i;
        this.b = i > 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof u2) && this.a == ((u2) obj).a;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.r(new StringBuilder("UserFreeTrialAvailability(freeTrialDurationInDays="), this.a, ")");
    }
}
