package com.quizlet.features.questiontypes.truefalse;

/* loaded from: classes3.dex */
public final class a {
    public final boolean a;
    public final boolean b;

    public a(boolean z, boolean z2) {
        this.a = z;
        this.b = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && this.b == aVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (Boolean.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "AudioState(isTopPlaying=" + this.a + ", isBottomPlaying=" + this.b + ")";
    }
}
