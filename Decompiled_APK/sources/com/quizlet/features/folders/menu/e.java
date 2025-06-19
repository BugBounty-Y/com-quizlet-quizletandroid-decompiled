package com.quizlet.features.folders.menu;

/* loaded from: classes3.dex */
public final class e implements i {
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

    @Override // com.quizlet.features.folders.menu.i
    public final boolean isEnabled() {
        return this.a;
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("AddTag(isEnabled="), this.a);
    }
}
