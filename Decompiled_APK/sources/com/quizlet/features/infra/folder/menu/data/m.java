package com.quizlet.features.infra.folder.menu.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m implements q {
    public final String a;
    public final AddToFolderException b;

    public m(String folderName, AddToFolderException exception) {
        Intrinsics.checkNotNullParameter(folderName, "folderName");
        Intrinsics.checkNotNullParameter(exception, "exception");
        this.a = folderName;
        this.b = exception;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof m)) {
            return false;
        }
        m mVar = (m) obj;
        return Intrinsics.b(this.a, mVar.a) && Intrinsics.b(this.b, mVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "AddRemoveFailure(folderName=" + this.a + ", exception=" + this.b + ")";
    }
}
