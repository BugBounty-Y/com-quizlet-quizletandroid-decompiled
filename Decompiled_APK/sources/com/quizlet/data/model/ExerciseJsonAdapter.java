package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class ExerciseJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;
    public final com.squareup.moshi.l d;
    public final com.squareup.moshi.l e;

    public ExerciseJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("id", "mediaExerciseId", "name", "hasSolution", "webUrl");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        kotlin.collections.M m = kotlin.collections.M.a;
        com.squareup.moshi.l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(String.class, m, "mediaExerciseId");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        com.squareup.moshi.l lVarA3 = moshi.a(String.class, m, "name");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        com.squareup.moshi.l lVarA4 = moshi.a(Boolean.TYPE, m, "hasSolution");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        Boolean bool = null;
        String str = null;
        String str2 = null;
        String str3 = null;
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
            } else if (iK0 != 1) {
                com.squareup.moshi.l lVar = this.d;
                if (iK0 == 2) {
                    str2 = (String) lVar.a(reader);
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.k("name", "name", reader);
                    }
                } else if (iK0 == 3) {
                    bool = (Boolean) this.e.a(reader);
                    if (bool == null) {
                        throw com.squareup.moshi.internal.b.k("hasSolution", "hasSolution", reader);
                    }
                } else if (iK0 == 4 && (str3 = (String) lVar.a(reader)) == null) {
                    throw com.squareup.moshi.internal.b.k("webUrl", "webUrl", reader);
                }
            } else {
                str = (String) this.c.a(reader);
            }
        }
        reader.i();
        Boolean bool2 = bool;
        if (l == null) {
            throw com.squareup.moshi.internal.b.e("id", "id", reader);
        }
        long jLongValue = l.longValue();
        if (str2 == null) {
            throw com.squareup.moshi.internal.b.e("name", "name", reader);
        }
        if (bool2 == null) {
            throw com.squareup.moshi.internal.b.e("hasSolution", "hasSolution", reader);
        }
        boolean zBooleanValue = bool2.booleanValue();
        if (str3 != null) {
            return new Exercise(jLongValue, str, str2, zBooleanValue, str3);
        }
        throw com.squareup.moshi.internal.b.e("webUrl", "webUrl", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        Exercise exercise = (Exercise) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (exercise == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        this.b.g(writer, Long.valueOf(exercise.a));
        writer.l("mediaExerciseId");
        this.c.g(writer, exercise.b);
        writer.l("name");
        com.squareup.moshi.l lVar = this.d;
        lVar.g(writer, exercise.c);
        writer.l("hasSolution");
        this.e.g(writer, Boolean.valueOf(exercise.d));
        writer.l("webUrl");
        lVar.g(writer, exercise.e);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(30, "GeneratedJsonAdapter(Exercise)", "toString(...)");
    }
}
