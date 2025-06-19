package com.quizlet.features.folders.changetags.data;

import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f {
    public static final f e = new f(false, kotlinx.collections.immutable.implementations.persistentOrderedSet.b.e, new com.quizlet.features.infra.folder.menu.data.b(-1, "", false, K.a), false);
    public final boolean a;
    public final kotlinx.collections.immutable.c b;
    public final com.quizlet.features.infra.folder.menu.data.b c;
    public final boolean d;

    public f(boolean z, kotlinx.collections.immutable.c selected, com.quizlet.features.infra.folder.menu.data.b folder, boolean z2) {
        Intrinsics.checkNotNullParameter(selected, "selected");
        Intrinsics.checkNotNullParameter(folder, "folder");
        this.a = z;
        this.b = selected;
        this.c = folder;
        this.d = z2;
    }

    public static f a(f fVar, boolean z, kotlinx.collections.immutable.c selected, com.quizlet.features.infra.folder.menu.data.b folder, boolean z2, int i) {
        if ((i & 1) != 0) {
            z = fVar.a;
        }
        if ((i & 2) != 0) {
            selected = fVar.b;
        }
        if ((i & 4) != 0) {
            folder = fVar.c;
        }
        if ((i & 8) != 0) {
            z2 = fVar.d;
        }
        fVar.getClass();
        Intrinsics.checkNotNullParameter(selected, "selected");
        Intrinsics.checkNotNullParameter(folder, "folder");
        return new f(z, selected, folder, z2);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return this.a == fVar.a && Intrinsics.b(this.b, fVar.b) && Intrinsics.b(this.c, fVar.c) && this.d == fVar.d;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.d) + ((this.c.hashCode() + ((this.b.hashCode() + (Boolean.hashCode(this.a) * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "ChangeTagsState(isSaveEnabled=" + this.a + ", selected=" + this.b + ", folder=" + this.c + ", isLoading=" + this.d + ")";
    }
}
