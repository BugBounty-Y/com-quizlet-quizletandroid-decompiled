package com.quizlet.features.infra.folder.tag.screenstates;

/* loaded from: classes3.dex */
public final class g implements j {
    public final int a;

    public g(int i) {
        this.a = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof g) && this.a == ((g) obj).a;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.r(new StringBuilder("RemoveTag(index="), this.a, ")");
    }
}
