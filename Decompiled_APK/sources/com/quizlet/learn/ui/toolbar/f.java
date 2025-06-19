package com.quizlet.learn.ui.toolbar;

/* loaded from: classes3.dex */
public final class f extends j {
    public final boolean b;

    public f(boolean z) {
        super(z);
        this.b = z;
    }

    @Override // com.quizlet.learn.ui.toolbar.j
    public final boolean a() {
        return this.b;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof f) && this.b == ((f) obj).b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("Checkpoint(showSettings="), this.b);
    }
}
