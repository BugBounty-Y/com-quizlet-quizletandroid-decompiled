package com.quizlet.data.model;

import com.quizlet.db.data.models.base.AssociationNames;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class CreatedFolderWithCreatorJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;

    public CreatedFolderWithCreatorJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("folder", AssociationNames.CREATOR);
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        kotlin.collections.M m = kotlin.collections.M.a;
        com.squareup.moshi.l lVarA = moshi.a(CreatedFolder.class, m, "folder");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(User.class, m, AssociationNames.CREATOR);
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        CreatedFolder createdFolder = null;
        User user = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                createdFolder = (CreatedFolder) this.b.a(reader);
                if (createdFolder == null) {
                    throw com.squareup.moshi.internal.b.k("folder", "folder", reader);
                }
            } else if (iK0 == 1) {
                user = (User) this.c.a(reader);
            }
        }
        reader.i();
        if (createdFolder != null) {
            return new CreatedFolderWithCreator(createdFolder, user);
        }
        throw com.squareup.moshi.internal.b.e("folder", "folder", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        CreatedFolderWithCreator createdFolderWithCreator = (CreatedFolderWithCreator) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (createdFolderWithCreator == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("folder");
        this.b.g(writer, createdFolderWithCreator.a);
        writer.l(AssociationNames.CREATOR);
        this.c.g(writer, createdFolderWithCreator.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(46, "GeneratedJsonAdapter(CreatedFolderWithCreator)", "toString(...)");
    }
}
