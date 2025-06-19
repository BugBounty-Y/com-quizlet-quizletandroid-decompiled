package com.quizlet.quizletandroid.ui.group;

/* loaded from: classes3.dex */
public final class e {
    public final boolean a;

    public e(boolean z) {
        this.a = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof e) && this.a == ((e) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("UserClassData(isMemberOfThisClass="), this.a);
    }
}
