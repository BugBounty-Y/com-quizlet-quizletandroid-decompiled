package com.quizlet.remote.model.union.folderwithcreatorinclass;

import androidx.compose.animation.d0;
import com.quizlet.remote.model.base.ApiResponse;
import com.quizlet.remote.model.classfolder.RemoteClassFolder;
import com.quizlet.remote.model.folder.RemoteFolder;
import com.quizlet.remote.model.user.RemoteUser;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class FolderWithCreatorInClassResponse extends ApiResponse {
    public final Models d;

    @m(generateAdapter = true)
    @Metadata
    public static final class Models {
        public final List a;
        public final List b;
        public final List c;

        public Models(@InterfaceC4853h(name = "classFolder") @NotNull List<RemoteClassFolder> classFolders, @InterfaceC4853h(name = "folder") @NotNull List<RemoteFolder> folders, @InterfaceC4853h(name = "user") @NotNull List<RemoteUser> users) {
            Intrinsics.checkNotNullParameter(classFolders, "classFolders");
            Intrinsics.checkNotNullParameter(folders, "folders");
            Intrinsics.checkNotNullParameter(users, "users");
            this.a = classFolders;
            this.b = folders;
            this.c = users;
        }

        @NotNull
        public final Models copy(@InterfaceC4853h(name = "classFolder") @NotNull List<RemoteClassFolder> classFolders, @InterfaceC4853h(name = "folder") @NotNull List<RemoteFolder> folders, @InterfaceC4853h(name = "user") @NotNull List<RemoteUser> users) {
            Intrinsics.checkNotNullParameter(classFolders, "classFolders");
            Intrinsics.checkNotNullParameter(folders, "folders");
            Intrinsics.checkNotNullParameter(users, "users");
            return new Models(classFolders, folders, users);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Models)) {
                return false;
            }
            Models models = (Models) obj;
            return Intrinsics.b(this.a, models.a) && Intrinsics.b(this.b, models.b) && Intrinsics.b(this.c, models.c);
        }

        public final int hashCode() {
            return this.c.hashCode() + d0.f(this.a.hashCode() * 31, 31, this.b);
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("Models(classFolders=");
            sb.append(this.a);
            sb.append(", folders=");
            sb.append(this.b);
            sb.append(", users=");
            return android.support.v4.media.session.a.n(")", sb, this.c);
        }
    }

    public FolderWithCreatorInClassResponse(@InterfaceC4853h(name = "models") Models models) {
        this.d = models;
    }

    @NotNull
    public final FolderWithCreatorInClassResponse copy(@InterfaceC4853h(name = "models") Models models) {
        return new FolderWithCreatorInClassResponse(models);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof FolderWithCreatorInClassResponse) && Intrinsics.b(this.d, ((FolderWithCreatorInClassResponse) obj).d);
    }

    public final int hashCode() {
        Models models = this.d;
        if (models == null) {
            return 0;
        }
        return models.hashCode();
    }

    public final String toString() {
        return "FolderWithCreatorInClassResponse(models=" + this.d + ")";
    }
}
