package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import androidx.compose.animation.d0;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.model.l, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4716l {
    public final boolean a;
    public final boolean b;
    public final boolean c;
    public final boolean d;
    public final boolean e;

    public C4716l(boolean z, boolean z2, boolean z3, boolean z4, boolean z5) {
        this.a = z;
        this.b = z2;
        this.c = z3;
        this.d = z4;
        this.e = z5;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4716l)) {
            return false;
        }
        C4716l c4716l = (C4716l) obj;
        return this.a == c4716l.a && this.b == c4716l.b && this.c == c4716l.c && this.d == c4716l.d && this.e == c4716l.e;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.e) + d0.g(d0.g(d0.g(Boolean.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CreationMenuUiState(showClassCreation=");
        sb.append(this.a);
        sb.append(", showNoteCreation=");
        sb.append(this.b);
        sb.append(", showFolderCreation=");
        sb.append(this.c);
        sb.append(", showPracticeTestCreation=");
        sb.append(this.d);
        sb.append(", creationMenuRedesign=");
        return android.support.v4.media.session.a.o(")", sb, this.e);
    }
}
