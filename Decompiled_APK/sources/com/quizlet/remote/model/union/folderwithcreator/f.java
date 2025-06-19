package com.quizlet.remote.model.union.folderwithcreator;

import com.quizlet.remote.model.folder.RemoteFolder;
import com.quizlet.remote.model.user.RemoteUser;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f {
    public final RemoteFolder a;
    public final RemoteUser b;

    public f(RemoteFolder folder, RemoteUser remoteUser) {
        Intrinsics.checkNotNullParameter(folder, "folder");
        this.a = folder;
        this.b = remoteUser;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return Intrinsics.b(this.a, fVar.a) && Intrinsics.b(this.b, fVar.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        RemoteUser remoteUser = this.b;
        return iHashCode + (remoteUser == null ? 0 : remoteUser.hashCode());
    }

    public final String toString() {
        return "RemoteFolderWithCreator(folder=" + this.a + ", creator=" + this.b + ")";
    }
}
