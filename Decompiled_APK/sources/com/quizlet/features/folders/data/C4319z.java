package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.data.z, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4319z implements InterfaceC4315x {
    public final String a;
    public final int b;
    public final boolean c;

    public C4319z(String noteId, int i, boolean z) {
        Intrinsics.checkNotNullParameter(noteId, "noteId");
        this.a = noteId;
        this.b = i;
        this.c = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4319z)) {
            return false;
        }
        C4319z c4319z = (C4319z) obj;
        return Intrinsics.b(this.a, c4319z.a) && this.b == c4319z.b && this.c == c4319z.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + androidx.compose.animation.d0.b(this.b, this.a.hashCode() * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("NoteClicked(noteId=");
        sb.append(this.a);
        sb.append(", index=");
        sb.append(this.b);
        sb.append(", isRecommended=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
