package com.quizlet.data.model;

import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class CourseJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;
    public final com.squareup.moshi.l d;
    public final com.squareup.moshi.l e;

    public CourseJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("id", "code", DBUserFields.Names.COUNTRY_CODE, "lastModified", "name", "timestamp");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        kotlin.collections.M m = kotlin.collections.M.a;
        com.squareup.moshi.l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(String.class, m, "code");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        com.squareup.moshi.l lVarA3 = moshi.a(Integer.TYPE, m, "lastModified");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        com.squareup.moshi.l lVarA4 = moshi.a(String.class, m, "name");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        Integer num = null;
        Long l2 = null;
        String str = null;
        String str2 = null;
        String str3 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            com.squareup.moshi.l lVar = this.c;
            com.squareup.moshi.l lVar2 = this.b;
            switch (iK0) {
                case -1:
                    reader.m0();
                    reader.n0();
                    break;
                case 0:
                    l = (Long) lVar2.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("id", "id", reader);
                    }
                    break;
                case 1:
                    str = (String) lVar.a(reader);
                    break;
                case 2:
                    str2 = (String) lVar.a(reader);
                    break;
                case 3:
                    num = (Integer) this.d.a(reader);
                    if (num == null) {
                        throw com.squareup.moshi.internal.b.k("lastModified", "lastModified", reader);
                    }
                    break;
                case 4:
                    str3 = (String) this.e.a(reader);
                    if (str3 == null) {
                        throw com.squareup.moshi.internal.b.k("name", "name", reader);
                    }
                    break;
                case 5:
                    l2 = (Long) lVar2.a(reader);
                    if (l2 == null) {
                        throw com.squareup.moshi.internal.b.k("timestamp", "timestamp", reader);
                    }
                    break;
            }
        }
        reader.i();
        Integer num2 = num;
        if (l == null) {
            throw com.squareup.moshi.internal.b.e("id", "id", reader);
        }
        long jLongValue = l.longValue();
        if (num2 == null) {
            throw com.squareup.moshi.internal.b.e("lastModified", "lastModified", reader);
        }
        int iIntValue = num2.intValue();
        if (str3 == null) {
            throw com.squareup.moshi.internal.b.e("name", "name", reader);
        }
        if (l2 != null) {
            return new Course(iIntValue, jLongValue, l2.longValue(), str, str2, str3);
        }
        throw com.squareup.moshi.internal.b.e("timestamp", "timestamp", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        Course course = (Course) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (course == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        Long lValueOf = Long.valueOf(course.a);
        com.squareup.moshi.l lVar = this.b;
        lVar.g(writer, lValueOf);
        writer.l("code");
        com.squareup.moshi.l lVar2 = this.c;
        lVar2.g(writer, course.b);
        writer.l(DBUserFields.Names.COUNTRY_CODE);
        lVar2.g(writer, course.c);
        writer.l("lastModified");
        this.d.g(writer, Integer.valueOf(course.d));
        writer.l("name");
        this.e.g(writer, course.e);
        writer.l("timestamp");
        lVar.g(writer, Long.valueOf(course.f));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(28, "GeneratedJsonAdapter(Course)", "toString(...)");
    }
}
