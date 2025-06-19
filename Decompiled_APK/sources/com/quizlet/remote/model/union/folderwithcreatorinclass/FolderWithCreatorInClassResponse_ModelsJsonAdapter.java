package com.quizlet.remote.model.union.folderwithcreatorinclass;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.classfolder.RemoteClassFolder;
import com.quizlet.remote.model.folder.RemoteFolder;
import com.quizlet.remote.model.union.folderwithcreatorinclass.FolderWithCreatorInClassResponse;
import com.quizlet.remote.model.user.RemoteUser;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.internal.Util$ParameterizedTypeImpl;
import com.squareup.moshi.internal.b;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class FolderWithCreatorInClassResponse_ModelsJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;

    public FolderWithCreatorInClassResponse_ModelsJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("classFolder", "folder", "user");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        Util$ParameterizedTypeImpl util$ParameterizedTypeImplF = H.f(List.class, RemoteClassFolder.class);
        M m = M.a;
        l lVarA = moshi.a(util$ParameterizedTypeImplF, m, "classFolders");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, RemoteFolder.class), m, "folders");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(H.f(List.class, RemoteUser.class), m, "users");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        List list = null;
        List list2 = null;
        List list3 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                list = (List) this.b.a(reader);
                if (list == null) {
                    throw b.k("classFolders", "classFolder", reader);
                }
            } else if (iK0 == 1) {
                list2 = (List) this.c.a(reader);
                if (list2 == null) {
                    throw b.k("folders", "folder", reader);
                }
            } else if (iK0 == 2 && (list3 = (List) this.d.a(reader)) == null) {
                throw b.k("users", "user", reader);
            }
        }
        reader.i();
        if (list == null) {
            throw b.e("classFolders", "classFolder", reader);
        }
        if (list2 == null) {
            throw b.e("folders", "folder", reader);
        }
        if (list3 != null) {
            return new FolderWithCreatorInClassResponse.Models(list, list2, list3);
        }
        throw b.e("users", "user", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        FolderWithCreatorInClassResponse.Models models = (FolderWithCreatorInClassResponse.Models) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (models == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("classFolder");
        this.b.g(writer, models.a);
        writer.l("folder");
        this.c.g(writer, models.b);
        writer.l("user");
        this.d.g(writer, models.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(61, "GeneratedJsonAdapter(FolderWithCreatorInClassResponse.Models)", "toString(...)");
    }
}
