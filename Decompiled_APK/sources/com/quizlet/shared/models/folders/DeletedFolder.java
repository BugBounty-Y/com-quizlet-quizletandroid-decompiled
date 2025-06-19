package com.quizlet.shared.models.folders;

import kotlin.Metadata;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class DeletedFolder extends b {

    @NotNull
    public static final Companion Companion = new Companion();
    public final long c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return DeletedFolder$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ DeletedFolder(int i, long j) {
        if (1 == (i & 1)) {
            this.c = j;
        } else {
            AbstractC5047c0.k(i, 1, DeletedFolder$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof DeletedFolder) && this.c == ((DeletedFolder) obj).c;
    }

    public final int hashCode() {
        return Long.hashCode(this.c);
    }

    public final String toString() {
        return android.support.v4.media.session.a.g(this.c, ")", new StringBuilder("DeletedFolder(id="));
    }
}
