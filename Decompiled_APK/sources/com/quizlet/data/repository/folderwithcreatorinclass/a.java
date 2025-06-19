package com.quizlet.data.repository.folderwithcreatorinclass;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final List a;
    public final List b;

    public a(List classFolders, List foldersWithCreator) {
        Intrinsics.checkNotNullParameter(classFolders, "classFolders");
        Intrinsics.checkNotNullParameter(foldersWithCreator, "foldersWithCreator");
        this.a = classFolders;
        this.b = foldersWithCreator;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "FolderWithCreatorInClassRemoteData(classFolders=" + this.a + ", foldersWithCreator=" + this.b + ")";
    }
}
