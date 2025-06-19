package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class DeletedFolderStudyMaterialJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;
    public final com.squareup.moshi.l d;

    public DeletedFolderStudyMaterialJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("id", "folderId", "studyMaterialId", "studyMaterialType");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        kotlin.collections.M m = kotlin.collections.M.a;
        com.squareup.moshi.l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(String.class, m, "studyMaterialId");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        com.squareup.moshi.l lVarA3 = moshi.a(com.quizlet.generated.enums.y1.class, m, "studyMaterialType");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        Long l2 = null;
        String str = null;
        com.quizlet.generated.enums.y1 y1Var = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 != -1) {
                com.squareup.moshi.l lVar = this.b;
                if (iK0 == 0) {
                    l = (Long) lVar.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("id", "id", reader);
                    }
                } else if (iK0 == 1) {
                    l2 = (Long) lVar.a(reader);
                    if (l2 == null) {
                        throw com.squareup.moshi.internal.b.k("folderId", "folderId", reader);
                    }
                } else if (iK0 == 2) {
                    str = (String) this.c.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("studyMaterialId", "studyMaterialId", reader);
                    }
                } else if (iK0 == 3 && (y1Var = (com.quizlet.generated.enums.y1) this.d.a(reader)) == null) {
                    throw com.squareup.moshi.internal.b.k("studyMaterialType", "studyMaterialType", reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        if (l == null) {
            throw com.squareup.moshi.internal.b.e("id", "id", reader);
        }
        long jLongValue = l.longValue();
        if (l2 == null) {
            throw com.squareup.moshi.internal.b.e("folderId", "folderId", reader);
        }
        long jLongValue2 = l2.longValue();
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("studyMaterialId", "studyMaterialId", reader);
        }
        if (y1Var != null) {
            return new DeletedFolderStudyMaterial(jLongValue, jLongValue2, str, y1Var);
        }
        throw com.squareup.moshi.internal.b.e("studyMaterialType", "studyMaterialType", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        DeletedFolderStudyMaterial deletedFolderStudyMaterial = (DeletedFolderStudyMaterial) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (deletedFolderStudyMaterial == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        Long lValueOf = Long.valueOf(deletedFolderStudyMaterial.a);
        com.squareup.moshi.l lVar = this.b;
        lVar.g(writer, lValueOf);
        writer.l("folderId");
        com.google.android.gms.measurement.internal.Z.k(deletedFolderStudyMaterial.b, lVar, writer, "studyMaterialId");
        this.c.g(writer, deletedFolderStudyMaterial.c);
        writer.l("studyMaterialType");
        this.d.g(writer, deletedFolderStudyMaterial.d);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(48, "GeneratedJsonAdapter(DeletedFolderStudyMaterial)", "toString(...)");
    }
}
