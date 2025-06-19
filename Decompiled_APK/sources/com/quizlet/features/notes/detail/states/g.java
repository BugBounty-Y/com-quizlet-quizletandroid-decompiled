package com.quizlet.features.notes.detail.states;

import androidx.compose.animation.d0;
import com.quizlet.data.model.NotesToValueInfo;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g implements h {
    public final NotesToValueInfo a;
    public final boolean b;
    public final com.quizlet.features.notes.data.c c;
    public final boolean d;
    public final boolean e;
    public final boolean f;

    public g(NotesToValueInfo notesInfo, boolean z, com.quizlet.features.notes.data.c cVar, boolean z2, boolean z3, boolean z4) {
        Intrinsics.checkNotNullParameter(notesInfo, "notesInfo");
        this.a = notesInfo;
        this.b = z;
        this.c = cVar;
        this.d = z2;
        this.e = z3;
        this.f = z4;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return Intrinsics.b(this.a, gVar.a) && this.b == gVar.b && Intrinsics.b(this.c, gVar.c) && this.d == gVar.d && this.e == gVar.e && this.f == gVar.f;
    }

    public final int hashCode() {
        int iG = d0.g(d0.b(60, this.a.hashCode() * 31, 31), 31, this.b);
        com.quizlet.features.notes.data.c cVar = this.c;
        return Boolean.hashCode(this.f) + d0.g(d0.g((iG + (cVar == null ? 0 : cVar.hashCode())) * 31, 31, this.d), 31, this.e);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Success(notesInfo=");
        sb.append(this.a);
        sb.append(", maximumTitleCharacter=60, uploadedByUser=");
        sb.append(this.b);
        sb.append(", editTitleInfo=");
        sb.append(this.c);
        sb.append(", isLearnStudyModeLocked=");
        sb.append(this.d);
        sb.append(", isTestStudyModeLocked=");
        sb.append(this.e);
        sb.append(", displayFlashcardsOnly=");
        return android.support.v4.media.session.a.o(")", sb, this.f);
    }
}
