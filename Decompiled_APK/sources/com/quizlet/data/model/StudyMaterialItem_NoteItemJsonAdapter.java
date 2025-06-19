package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class StudyMaterialItem_NoteItemJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;

    public StudyMaterialItem_NoteItemJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("studyMaterial", "data");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        kotlin.collections.M m = kotlin.collections.M.a;
        com.squareup.moshi.l lVarA = moshi.a(M1.class, m, "studyMaterial");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(NotesToValueInfo.class, m, "data");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        M1 m1 = null;
        NotesToValueInfo notesToValueInfo = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                m1 = (M1) this.b.a(reader);
                if (m1 == null) {
                    throw com.squareup.moshi.internal.b.k("studyMaterial", "studyMaterial", reader);
                }
            } else if (iK0 == 1 && (notesToValueInfo = (NotesToValueInfo) this.c.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("data_", "data", reader);
            }
        }
        reader.i();
        if (m1 == null) {
            throw com.squareup.moshi.internal.b.e("studyMaterial", "studyMaterial", reader);
        }
        if (notesToValueInfo != null) {
            return new StudyMaterialItem$NoteItem(m1, notesToValueInfo);
        }
        throw com.squareup.moshi.internal.b.e("data_", "data", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        StudyMaterialItem$NoteItem studyMaterialItem$NoteItem = (StudyMaterialItem$NoteItem) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (studyMaterialItem$NoteItem == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("studyMaterial");
        this.b.g(writer, studyMaterialItem$NoteItem.a);
        writer.l("data");
        this.c.g(writer, studyMaterialItem$NoteItem.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(48, "GeneratedJsonAdapter(StudyMaterialItem.NoteItem)", "toString(...)");
    }
}
