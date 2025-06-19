package com.quizlet.data.model;

import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class ExerciseGroupJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;
    public final com.squareup.moshi.l d;
    public final com.squareup.moshi.l e;
    public final com.squareup.moshi.l f;

    public ExerciseGroupJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("id", "hasSolutions", "title", "page", "exercises");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        kotlin.collections.M m = kotlin.collections.M.a;
        com.squareup.moshi.l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(Boolean.TYPE, m, "hasSolutions");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        com.squareup.moshi.l lVarA3 = moshi.a(String.class, m, "title");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        com.squareup.moshi.l lVarA4 = moshi.a(String.class, m, "page");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        com.squareup.moshi.l lVarA5 = moshi.a(com.squareup.moshi.H.f(List.class, Exercise.class), m, "exercises");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        Boolean bool = null;
        String str = null;
        String str2 = null;
        List list = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                l = (Long) this.b.a(reader);
                if (l == null) {
                    throw com.squareup.moshi.internal.b.k("id", "id", reader);
                }
            } else if (iK0 == 1) {
                bool = (Boolean) this.c.a(reader);
                if (bool == null) {
                    throw com.squareup.moshi.internal.b.k("hasSolutions", "hasSolutions", reader);
                }
            } else if (iK0 == 2) {
                str = (String) this.d.a(reader);
                if (str == null) {
                    throw com.squareup.moshi.internal.b.k("title", "title", reader);
                }
            } else if (iK0 == 3) {
                str2 = (String) this.e.a(reader);
            } else if (iK0 == 4 && (list = (List) this.f.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("exercises", "exercises", reader);
            }
        }
        reader.i();
        if (l == null) {
            throw com.squareup.moshi.internal.b.e("id", "id", reader);
        }
        long jLongValue = l.longValue();
        if (bool == null) {
            throw com.squareup.moshi.internal.b.e("hasSolutions", "hasSolutions", reader);
        }
        boolean zBooleanValue = bool.booleanValue();
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("title", "title", reader);
        }
        if (list != null) {
            return new ExerciseGroup(jLongValue, str, str2, zBooleanValue, list);
        }
        throw com.squareup.moshi.internal.b.e("exercises", "exercises", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        ExerciseGroup exerciseGroup = (ExerciseGroup) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (exerciseGroup == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        this.b.g(writer, Long.valueOf(exerciseGroup.a));
        writer.l("hasSolutions");
        this.c.g(writer, Boolean.valueOf(exerciseGroup.b));
        writer.l("title");
        this.d.g(writer, exerciseGroup.c);
        writer.l("page");
        this.e.g(writer, exerciseGroup.d);
        writer.l("exercises");
        this.f.g(writer, exerciseGroup.e);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(35, "GeneratedJsonAdapter(ExerciseGroup)", "toString(...)");
    }
}
