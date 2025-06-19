package com.quizlet.shared.models.folders;

import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import org.jetbrains.annotations.NotNull;
import serialization.e;

@f
@Metadata
/* loaded from: classes3.dex */
public final class ListsOfFolders extends e {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] c = {new C5048d(Folders$$serializer.INSTANCE, 0)};
    public final List b;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return ListsOfFolders$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ ListsOfFolders(int i, List list) {
        if (1 == (i & 1)) {
            this.b = list;
        } else {
            AbstractC5047c0.k(i, 1, ListsOfFolders$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof ListsOfFolders) && Intrinsics.b(this.b, ((ListsOfFolders) obj).b);
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("ListsOfFolders(folders="), this.b);
    }
}
