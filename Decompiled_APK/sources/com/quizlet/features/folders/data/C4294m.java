package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.data.m, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4294m implements T {
    public final String a;
    public final long b;
    public final long c;

    public C4294m(long j, long j2, String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.a = name;
        this.b = j;
        this.c = j2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4294m)) {
            return false;
        }
        C4294m c4294m = (C4294m) obj;
        return Intrinsics.b(this.a, c4294m.a) && this.b == c4294m.b && this.c == c4294m.c;
    }

    public final int hashCode() {
        return Long.hashCode(this.c) + androidx.compose.animation.d0.d(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FolderEdited(name=");
        sb.append(this.a);
        sb.append(", schoolId=");
        sb.append(this.b);
        sb.append(", courseId=");
        return android.support.v4.media.session.a.g(this.c, ")", sb);
    }
}
