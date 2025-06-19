package com.quizlet.features.notes.data;

import androidx.compose.animation.d0;

/* loaded from: classes3.dex */
public final class c {
    public final boolean a;
    public final boolean b;
    public final b c;

    public /* synthetic */ c(int i) {
        this((i & 2) == 0, (i & 4) != 0 ? null : b.b);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a == cVar.a && this.b == cVar.b && this.c == cVar.c;
    }

    public final int hashCode() {
        int iG = d0.g(Boolean.hashCode(this.a) * 31, 31, this.b);
        b bVar = this.c;
        return iG + (bVar == null ? 0 : bVar.hashCode());
    }

    public final String toString() {
        return "EditTitleInfo(shouldShowDialog=" + this.a + ", isLoading=" + this.b + ", errorMessage=" + this.c + ")";
    }

    public c(boolean z, b bVar) {
        this.a = true;
        this.b = z;
        this.c = bVar;
    }
}
