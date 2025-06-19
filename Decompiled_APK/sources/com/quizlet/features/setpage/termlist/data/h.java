package com.quizlet.features.setpage.termlist.data;

import com.google.android.gms.internal.mlkit_vision_common.C;

/* loaded from: classes3.dex */
public final class h extends C {
    public final long a;
    public final boolean b;

    public h(long j, boolean z) {
        this.a = j;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return this.a == hVar.a && this.b == hVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "ToggleStar(termId=" + this.a + ", isStarred=" + this.b + ")";
    }
}
