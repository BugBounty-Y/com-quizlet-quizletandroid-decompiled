package com.quizlet.quizletandroid.ui.startpage.nav2.screenstates;

/* loaded from: classes3.dex */
public final class o {
    public final boolean a;
    public final boolean b;

    public o(boolean z, boolean z2) {
        this.a = z;
        this.b = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof o)) {
            return false;
        }
        o oVar = (o) obj;
        return this.a == oVar.a && this.b == oVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (Boolean.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MainSectionState(isLoaded=");
        sb.append(this.a);
        sb.append(", isEmpty=");
        return android.support.v4.media.session.a.o(")", sb, this.b);
    }
}
