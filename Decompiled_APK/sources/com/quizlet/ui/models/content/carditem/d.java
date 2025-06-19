package com.quizlet.ui.models.content.carditem;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public final String a;
    public final String b;
    public final String c;
    public final boolean d;
    public final String e;
    public final int f;

    public d(int i, String noteUuid, String noteTitle, String username, String imageURL, boolean z) {
        Intrinsics.checkNotNullParameter(noteUuid, "noteUuid");
        Intrinsics.checkNotNullParameter(noteTitle, "noteTitle");
        Intrinsics.checkNotNullParameter(username, "username");
        Intrinsics.checkNotNullParameter(imageURL, "imageURL");
        this.a = noteUuid;
        this.b = noteTitle;
        this.c = username;
        this.d = z;
        this.e = imageURL;
        this.f = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return Intrinsics.b(this.a, dVar.a) && Intrinsics.b(this.b, dVar.b) && Intrinsics.b(this.c, dVar.c) && this.d == dVar.d && Intrinsics.b(this.e, dVar.e) && this.f == dVar.f;
    }

    public final int hashCode() {
        return Integer.hashCode(this.f) + d0.e(d0.g(d0.e(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("NotesCardUiData(noteUuid=");
        sb.append(this.a);
        sb.append(", noteTitle=");
        sb.append(this.b);
        sb.append(", username=");
        sb.append(this.c);
        sb.append(", isVerified=");
        sb.append(this.d);
        sb.append(", imageURL=");
        sb.append(this.e);
        sb.append(", userBadge=");
        return android.support.v4.media.session.a.r(sb, this.f, ")");
    }
}
