package com.quizlet.remote.model.explanations.toc;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.internal.b;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RemoteExerciseJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;

    public RemoteExerciseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("id", "mediaExerciseId", "exerciseName", "hasSolution", "_webUrl");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(String.class, m, "mediaExerciseId");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(String.class, m, "name");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(Boolean.TYPE, m, "hasSolution");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
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
                    throw b.k("id", "id", reader);
                }
            } else if (iK0 != 1) {
                l lVar = this.d;
                if (iK0 == 2) {
                    str2 = (String) lVar.a(reader);
                    if (str2 == null) {
                        throw b.k("name", "exerciseName", reader);
                    }
                } else if (iK0 == 3) {
                    bool = (Boolean) this.e.a(reader);
                    if (bool == null) {
                        throw b.k("hasSolution", "hasSolution", reader);
                    }
                } else if (iK0 == 4 && (str3 = (String) lVar.a(reader)) == null) {
                    throw b.k("webUrl", "_webUrl", reader);
                }
            } else {
                str = (String) this.c.a(reader);
            }
        }
        reader.i();
        Boolean bool2 = bool;
        if (l == null) {
            throw b.e("id", "id", reader);
        }
        long jLongValue = l.longValue();
        if (str2 == null) {
            throw b.e("name", "exerciseName", reader);
        }
        if (bool2 == null) {
            throw b.e("hasSolution", "hasSolution", reader);
        }
        boolean zBooleanValue = bool2.booleanValue();
        if (str3 != null) {
            return new RemoteExercise(jLongValue, str, str2, zBooleanValue, str3);
        }
        throw b.e("webUrl", "_webUrl", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteExercise remoteExercise = (RemoteExercise) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteExercise == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        this.b.g(writer, Long.valueOf(remoteExercise.a));
        writer.l("mediaExerciseId");
        this.c.g(writer, remoteExercise.b);
        writer.l("exerciseName");
        l lVar = this.d;
        lVar.g(writer, remoteExercise.c);
        writer.l("hasSolution");
        this.e.g(writer, Boolean.valueOf(remoteExercise.d));
        writer.l("_webUrl");
        lVar.g(writer, remoteExercise.e);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(36, "GeneratedJsonAdapter(RemoteExercise)", "toString(...)");
    }
}
