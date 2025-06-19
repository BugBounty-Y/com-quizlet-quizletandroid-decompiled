package com.quizlet.remote.model.folderstudymaterial;

import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class FolderStudyMaterialsRequestJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;
    public final com.squareup.moshi.l d;

    public FolderStudyMaterialsRequestJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("folderId", "studyMaterialId", "studyMaterialType");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        com.squareup.moshi.l lVarA = moshi.a(Long.TYPE, m, "folderId");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(String.class, m, "studyMaterialId");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        com.squareup.moshi.l lVarA3 = moshi.a(Integer.TYPE, m, "studyMaterialType");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        String str = null;
        Integer num = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                l = (Long) this.b.a(reader);
                if (l == null) {
                    throw com.squareup.moshi.internal.b.k("folderId", "folderId", reader);
                }
            } else if (iK0 == 1) {
                str = (String) this.c.a(reader);
                if (str == null) {
                    throw com.squareup.moshi.internal.b.k("studyMaterialId", "studyMaterialId", reader);
                }
            } else if (iK0 == 2 && (num = (Integer) this.d.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("studyMaterialType", "studyMaterialType", reader);
            }
        }
        reader.i();
        if (l == null) {
            throw com.squareup.moshi.internal.b.e("folderId", "folderId", reader);
        }
        long jLongValue = l.longValue();
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("studyMaterialId", "studyMaterialId", reader);
        }
        if (num != null) {
            return new FolderStudyMaterialsRequest(num.intValue(), jLongValue, str);
        }
        throw com.squareup.moshi.internal.b.e("studyMaterialType", "studyMaterialType", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        FolderStudyMaterialsRequest folderStudyMaterialsRequest = (FolderStudyMaterialsRequest) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (folderStudyMaterialsRequest == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("folderId");
        this.b.g(writer, Long.valueOf(folderStudyMaterialsRequest.a));
        writer.l("studyMaterialId");
        this.c.g(writer, folderStudyMaterialsRequest.b);
        writer.l("studyMaterialType");
        this.d.g(writer, Integer.valueOf(folderStudyMaterialsRequest.c));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(49, "GeneratedJsonAdapter(FolderStudyMaterialsRequest)", "toString(...)");
    }
}
