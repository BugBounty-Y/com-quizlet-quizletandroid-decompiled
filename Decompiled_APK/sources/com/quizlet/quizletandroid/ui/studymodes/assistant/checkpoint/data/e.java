package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data;

/* loaded from: classes3.dex */
public final class e implements f {
    public final long a;
    public final boolean b;

    public e(long j, boolean z) {
        this.a = j;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return this.a == eVar.a && this.b == eVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "StarButtonClicked(termId=" + this.a + ", isStarred=" + this.b + ")";
    }
}
