package com.quizlet.remote.model.course;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
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
public final class RemoteCourseJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;

    public RemoteCourseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("id", "code", DBUserFields.Names.COUNTRY_CODE, "lastModified", "name", "timestamp");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(String.class, m, "code");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Integer.TYPE, m, "lastModified");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(String.class, m, "name");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(Long.class, m, "timestamp");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        Integer num = null;
        String str = null;
        String str2 = null;
        String str3 = null;
        Long l2 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            l lVar = this.c;
            switch (iK0) {
                case -1:
                    reader.m0();
                    reader.n0();
                    break;
                case 0:
                    l = (Long) this.b.a(reader);
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
                    l2 = (Long) this.f.a(reader);
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
        if (str3 != null) {
            return new RemoteCourse(jLongValue, str, str2, iIntValue, str3, l2);
        }
        throw com.squareup.moshi.internal.b.e("name", "name", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteCourse remoteCourse = (RemoteCourse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteCourse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        this.b.g(writer, Long.valueOf(remoteCourse.a));
        writer.l("code");
        l lVar = this.c;
        lVar.g(writer, remoteCourse.b);
        writer.l(DBUserFields.Names.COUNTRY_CODE);
        lVar.g(writer, remoteCourse.c);
        writer.l("lastModified");
        this.d.g(writer, Integer.valueOf(remoteCourse.d));
        writer.l("name");
        this.e.g(writer, remoteCourse.e);
        writer.l("timestamp");
        this.f.g(writer, remoteCourse.f);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(34, "GeneratedJsonAdapter(RemoteCourse)", "toString(...)");
    }
}
