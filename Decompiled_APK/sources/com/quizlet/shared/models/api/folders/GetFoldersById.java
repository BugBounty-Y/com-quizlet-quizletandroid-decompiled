package com.quizlet.shared.models.api.folders;

import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import kotlinx.serialization.internal.P;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class GetFoldersById extends a {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] d = {new C5048d(P.a, 0), null};
    public final List b;
    public final boolean c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return GetFoldersById$$serializer.INSTANCE;
        }
    }

    public GetFoldersById(boolean z, int i, List list) {
        if (1 != (i & 1)) {
            AbstractC5047c0.k(i, 1, GetFoldersById$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.b = list;
        if ((i & 2) == 0) {
            this.c = false;
        } else {
            this.c = z;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof GetFoldersById)) {
            return false;
        }
        GetFoldersById getFoldersById = (GetFoldersById) obj;
        return Intrinsics.b(this.b, getFoldersById.b) && this.c == getFoldersById.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + (this.b.hashCode() * 31);
    }

    public final String toString() {
        return "GetFoldersById(ids=" + this.b + ", includeCreators=" + this.c + ")";
    }
}
