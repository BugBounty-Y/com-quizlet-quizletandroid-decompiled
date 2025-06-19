package com.quizlet.quizletandroid.ui.startpage.nav2.screenstates;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class p {
    public o a;
    public o b;
    public o c;
    public o d;
    public o e;
    public o f;
    public o g;
    public o h;

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof p)) {
            return false;
        }
        p pVar = (p) obj;
        return Intrinsics.b(this.a, pVar.a) && Intrinsics.b(this.b, pVar.b) && Intrinsics.b(this.c, pVar.c) && Intrinsics.b(this.d, pVar.d) && Intrinsics.b(this.e, pVar.e) && Intrinsics.b(this.f, pVar.f) && Intrinsics.b(this.g, pVar.g) && Intrinsics.b(this.h, pVar.h);
    }

    public final int hashCode() {
        return this.h.hashCode() + ((this.g.hashCode() + ((this.f.hashCode() + ((this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31)) * 31)) * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "LoadedState(explanationsState=" + this.a + ", studySetsState=" + this.b + ", foldersState=" + this.c + ", classesState=" + this.d + ", behaviorRecsState=" + this.e + ", schoolCourseRecsState=" + this.f + ", ageLocationRecsState=" + this.g + ", magicNotesState=" + this.h + ")";
    }
}
