package com.quizlet.remote.model.explanations.search;

import com.google.android.gms.measurement.internal.Z;
import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
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
public final class RemoteSearchResultQuestionJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;

    public RemoteSearchResultQuestionJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("id", "prompt", "clarification", "slug", "subjectIds", "createdTimestamp", "_humanized", "_webUrl");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(String.class, m, "prompt");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(String.class, m, "clarification");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(H.f(List.class, Integer.class), m, "subjectIds");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        Long l2 = null;
        String str = null;
        String str2 = null;
        String str3 = null;
        List list = null;
        String str4 = null;
        String str5 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            Long l3 = l;
            l lVar = this.c;
            Long l4 = l2;
            l lVar2 = this.b;
            l lVar3 = this.d;
            switch (iK0) {
                case -1:
                    reader.m0();
                    reader.n0();
                    l = l3;
                    l2 = l4;
                case 0:
                    l = (Long) lVar2.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("id", "id", reader);
                    }
                    l2 = l4;
                case 1:
                    str = (String) lVar.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("prompt", "prompt", reader);
                    }
                    l = l3;
                    l2 = l4;
                case 2:
                    str2 = (String) lVar3.a(reader);
                    l = l3;
                    l2 = l4;
                case 3:
                    str3 = (String) lVar.a(reader);
                    if (str3 == null) {
                        throw com.squareup.moshi.internal.b.k("slug", "slug", reader);
                    }
                    l = l3;
                    l2 = l4;
                case 4:
                    list = (List) this.e.a(reader);
                    if (list == null) {
                        throw com.squareup.moshi.internal.b.k("subjectIds", "subjectIds", reader);
                    }
                    l = l3;
                    l2 = l4;
                case 5:
                    l2 = (Long) lVar2.a(reader);
                    if (l2 == null) {
                        throw com.squareup.moshi.internal.b.k("createdTimestamp", "createdTimestamp", reader);
                    }
                    l = l3;
                case 6:
                    str4 = (String) lVar3.a(reader);
                    l = l3;
                    l2 = l4;
                case 7:
                    str5 = (String) lVar3.a(reader);
                    l = l3;
                    l2 = l4;
                default:
                    l = l3;
                    l2 = l4;
            }
        }
        Long l5 = l;
        Long l6 = l2;
        reader.i();
        if (l5 == null) {
            throw com.squareup.moshi.internal.b.e("id", "id", reader);
        }
        long jLongValue = l5.longValue();
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("prompt", "prompt", reader);
        }
        if (str3 == null) {
            throw com.squareup.moshi.internal.b.e("slug", "slug", reader);
        }
        if (list == null) {
            throw com.squareup.moshi.internal.b.e("subjectIds", "subjectIds", reader);
        }
        if (l6 != null) {
            return new RemoteSearchResultQuestion(jLongValue, str, str2, str3, list, l6.longValue(), str4, str5);
        }
        throw com.squareup.moshi.internal.b.e("createdTimestamp", "createdTimestamp", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteSearchResultQuestion remoteSearchResultQuestion = (RemoteSearchResultQuestion) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteSearchResultQuestion == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        Long lValueOf = Long.valueOf(remoteSearchResultQuestion.a);
        l lVar = this.b;
        lVar.g(writer, lValueOf);
        writer.l("prompt");
        l lVar2 = this.c;
        lVar2.g(writer, remoteSearchResultQuestion.b);
        writer.l("clarification");
        l lVar3 = this.d;
        lVar3.g(writer, remoteSearchResultQuestion.c);
        writer.l("slug");
        lVar2.g(writer, remoteSearchResultQuestion.d);
        writer.l("subjectIds");
        this.e.g(writer, remoteSearchResultQuestion.e);
        writer.l("createdTimestamp");
        Z.k(remoteSearchResultQuestion.f, lVar, writer, "_humanized");
        lVar3.g(writer, remoteSearchResultQuestion.g);
        writer.l("_webUrl");
        lVar3.g(writer, remoteSearchResultQuestion.h);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(48, "GeneratedJsonAdapter(RemoteSearchResultQuestion)", "toString(...)");
    }
}
