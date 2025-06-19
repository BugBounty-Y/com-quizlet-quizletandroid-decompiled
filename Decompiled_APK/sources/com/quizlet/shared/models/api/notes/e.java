package com.quizlet.shared.models.api.notes;

import androidx.compose.animation.d0;

/* loaded from: classes3.dex */
public final class e extends h {
    public final int c;
    public final int d;
    public final boolean e;

    public e(int i, int i2, boolean z) {
        super(null);
        this.c = i;
        this.d = i2;
        this.e = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return this.c == eVar.c && this.d == eVar.d && this.e == eVar.e;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.e) + d0.b(this.d, Integer.hashCode(this.c) * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AllForUser(limit=");
        sb.append(this.c);
        sb.append(", offset=");
        sb.append(this.d);
        sb.append(", includeAllArtifacts=");
        return android.support.v4.media.session.a.o(")", sb, this.e);
    }
}
