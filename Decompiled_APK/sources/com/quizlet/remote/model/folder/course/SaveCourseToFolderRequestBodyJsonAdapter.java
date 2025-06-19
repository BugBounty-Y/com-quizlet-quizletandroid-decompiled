package com.quizlet.remote.model.folder.course;

import com.airbnb.lottie.parser.moshi.c;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.DBGroupFields;
import com.squareup.moshi.D;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class SaveCourseToFolderRequestBodyJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;

    public SaveCourseToFolderRequestBodyJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("courseId", DBGroupFields.Names.SCHOOL_ID, "shouldReplace");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "courseId");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Boolean.TYPE, m, "shouldReplace");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        Long l2 = null;
        Boolean bool = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 != -1) {
                l lVar = this.b;
                if (iK0 == 0) {
                    l = (Long) lVar.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("courseId", "courseId", reader);
                    }
                } else if (iK0 == 1) {
                    l2 = (Long) lVar.a(reader);
                    if (l2 == null) {
                        throw com.squareup.moshi.internal.b.k(DBGroupFields.Names.SCHOOL_ID, DBGroupFields.Names.SCHOOL_ID, reader);
                    }
                } else if (iK0 == 2 && (bool = (Boolean) this.c.a(reader)) == null) {
                    throw com.squareup.moshi.internal.b.k("shouldReplace", "shouldReplace", reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        Long l3 = l;
        if (l3 == null) {
            throw com.squareup.moshi.internal.b.e("courseId", "courseId", reader);
        }
        long jLongValue = l3.longValue();
        if (l2 == null) {
            throw com.squareup.moshi.internal.b.e(DBGroupFields.Names.SCHOOL_ID, DBGroupFields.Names.SCHOOL_ID, reader);
        }
        long jLongValue2 = l2.longValue();
        if (bool != null) {
            return new SaveCourseToFolderRequestBody(jLongValue, jLongValue2, bool.booleanValue());
        }
        throw com.squareup.moshi.internal.b.e("shouldReplace", "shouldReplace", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        SaveCourseToFolderRequestBody saveCourseToFolderRequestBody = (SaveCourseToFolderRequestBody) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (saveCourseToFolderRequestBody == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("courseId");
        Long lValueOf = Long.valueOf(saveCourseToFolderRequestBody.a);
        l lVar = this.b;
        lVar.g(writer, lValueOf);
        writer.l(DBGroupFields.Names.SCHOOL_ID);
        Z.k(saveCourseToFolderRequestBody.b, lVar, writer, "shouldReplace");
        this.c.g(writer, Boolean.valueOf(saveCourseToFolderRequestBody.c));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(51, "GeneratedJsonAdapter(SaveCourseToFolderRequestBody)", "toString(...)");
    }
}
