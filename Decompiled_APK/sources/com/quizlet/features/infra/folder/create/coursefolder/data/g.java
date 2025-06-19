package com.quizlet.features.infra.folder.create.coursefolder.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g implements j {
    public final String a;
    public final com.quizlet.features.infra.folder.create.data.b b;
    public final com.quizlet.features.infra.folder.create.data.i c;
    public final Long d;

    public g(String initialFolderTitle, com.quizlet.features.infra.folder.create.data.b createFolderState, com.quizlet.features.infra.folder.create.data.i iVar, Long l) {
        Intrinsics.checkNotNullParameter(initialFolderTitle, "initialFolderTitle");
        Intrinsics.checkNotNullParameter(createFolderState, "createFolderState");
        this.a = initialFolderTitle;
        this.b = createFolderState;
        this.c = iVar;
        this.d = l;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return Intrinsics.b(this.a, gVar.a) && this.b == gVar.b && Intrinsics.b(this.c, gVar.c) && Intrinsics.b(this.d, gVar.d);
    }

    public final int hashCode() {
        int iHashCode = (this.b.hashCode() + (this.a.hashCode() * 31)) * 31;
        com.quizlet.features.infra.folder.create.data.i iVar = this.c;
        int iHashCode2 = (iHashCode + (iVar == null ? 0 : iVar.hashCode())) * 31;
        Long l = this.d;
        return iHashCode2 + (l != null ? l.hashCode() : 0);
    }

    public final String toString() {
        return "ModalShown(initialFolderTitle=" + this.a + ", createFolderState=" + this.b + ", schoolCourseUiData=" + this.c + ", folderId=" + this.d + ")";
    }
}
