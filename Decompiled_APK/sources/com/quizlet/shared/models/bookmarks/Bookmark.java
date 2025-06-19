package com.quizlet.shared.models.bookmarks;

import android.support.v4.media.session.a;
import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;
import serialization.e;

@f
@Metadata
/* loaded from: classes3.dex */
public final class Bookmark extends e {

    @NotNull
    public static final Companion Companion = new Companion();
    public final long b;
    public final long c;
    public final long d;
    public final long e;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return Bookmark$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ Bookmark(long j, long j2, long j3, long j4, int i) {
        if (15 != (i & 15)) {
            AbstractC5047c0.k(i, 15, Bookmark$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.b = j;
        this.c = j2;
        this.d = j3;
        this.e = j4;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Bookmark)) {
            return false;
        }
        Bookmark bookmark = (Bookmark) obj;
        return this.b == bookmark.b && this.c == bookmark.c && this.d == bookmark.d && this.e == bookmark.e;
    }

    public final int hashCode() {
        return Long.hashCode(this.e) + d0.d(d0.d(Long.hashCode(this.b) * 31, 31, this.c), 31, this.d);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Bookmark(personId=");
        sb.append(this.b);
        sb.append(", folderId=");
        sb.append(this.c);
        sb.append(", timestamp=");
        sb.append(this.d);
        sb.append(", lastModified=");
        return a.g(this.e, ")", sb);
    }
}
