package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class U implements W {
    public final Q0 a;
    public final boolean b;

    public U(Q0 folderUiData, boolean z) {
        Intrinsics.checkNotNullParameter(folderUiData, "folderUiData");
        this.a = folderUiData;
        this.b = z;
    }

    public static U a(U u, Q0 folderUiData, boolean z, int i) {
        if ((i & 1) != 0) {
            folderUiData = u.a;
        }
        if ((i & 2) != 0) {
            z = u.b;
        }
        u.getClass();
        Intrinsics.checkNotNullParameter(folderUiData, "folderUiData");
        return new U(folderUiData, z);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof U)) {
            return false;
        }
        U u = (U) obj;
        return Intrinsics.b(this.a, u.a) && this.b == u.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "Content(folderUiData=" + this.a + ", isSearchMode=" + this.b + ")";
    }
}
