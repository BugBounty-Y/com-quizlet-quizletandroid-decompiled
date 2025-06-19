package com.quizlet.features.settings.data.models;

/* loaded from: classes3.dex */
public final class i implements k {
    public final int a;

    public i(int i) {
        this.a = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof i) && this.a == ((i) obj).a;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.r(new StringBuilder("Free(upgradeButtonText="), this.a, ")");
    }
}
