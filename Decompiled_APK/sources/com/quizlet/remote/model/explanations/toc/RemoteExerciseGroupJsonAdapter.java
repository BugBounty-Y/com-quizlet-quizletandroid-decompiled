package com.quizlet.remote.model.explanations.toc;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.internal.b;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RemoteExerciseGroupJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;

    public RemoteExerciseGroupJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("id", "title", "page", "hasSolutions", "exercises");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(String.class, m, "title");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(String.class, m, "page");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(Boolean.TYPE, m, "hasSolutions");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(H.f(List.class, RemoteExercise.class), m, "exercises");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
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
                    throw b.k("id", "id", reader);
                }
            } else if (iK0 == 1) {
                str = (String) this.c.a(reader);
                if (str == null) {
                    throw b.k("title", "title", reader);
                }
            } else if (iK0 == 2) {
                str2 = (String) this.d.a(reader);
            } else if (iK0 == 3) {
                bool = (Boolean) this.e.a(reader);
                if (bool == null) {
                    throw b.k("hasSolutions", "hasSolutions", reader);
                }
            } else if (iK0 == 4) {
                list = (List) this.f.a(reader);
            }
        }
        reader.i();
        Boolean bool2 = bool;
        if (l == null) {
            throw b.e("id", "id", reader);
        }
        long jLongValue = l.longValue();
        if (str == null) {
            throw b.e("title", "title", reader);
        }
        if (bool2 != null) {
            return new RemoteExerciseGroup(jLongValue, str, str2, bool2.booleanValue(), list);
        }
        throw b.e("hasSolutions", "hasSolutions", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteExerciseGroup remoteExerciseGroup = (RemoteExerciseGroup) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteExerciseGroup == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        this.b.g(writer, Long.valueOf(remoteExerciseGroup.a));
        writer.l("title");
        this.c.g(writer, remoteExerciseGroup.b);
        writer.l("page");
        this.d.g(writer, remoteExerciseGroup.c);
        writer.l("hasSolutions");
        this.e.g(writer, Boolean.valueOf(remoteExerciseGroup.d));
        writer.l("exercises");
        this.f.g(writer, remoteExerciseGroup.e);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(41, "GeneratedJsonAdapter(RemoteExerciseGroup)", "toString(...)");
    }
}
