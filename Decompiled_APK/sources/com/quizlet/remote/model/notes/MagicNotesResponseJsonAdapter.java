package com.quizlet.remote.model.notes;

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
public final class MagicNotesResponseJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;

    public MagicNotesResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("uuid", "userId", "artifactUuids", "private", "extractedText", "createdAt");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "uuid");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Long.TYPE, m, "userId");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(H.f(List.class, String.class), m, "artifactUuids");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(Boolean.TYPE, m, "isPrivate");
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
        List list = null;
        String str2 = null;
        String str3 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            Long l2 = l;
            l lVar = this.b;
            switch (iK0) {
                case -1:
                    reader.m0();
                    reader.n0();
                    break;
                case 0:
                    str = (String) lVar.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("uuid", "uuid", reader);
                    }
                    break;
                case 1:
                    l = (Long) this.c.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("userId", "userId", reader);
                    }
                    continue;
                case 2:
                    list = (List) this.d.a(reader);
                    if (list == null) {
                        throw com.squareup.moshi.internal.b.k("artifactUuids", "artifactUuids", reader);
                    }
                    break;
                case 3:
                    bool = (Boolean) this.e.a(reader);
                    if (bool == null) {
                        throw com.squareup.moshi.internal.b.k("isPrivate", "private", reader);
                    }
                    break;
                case 4:
                    str2 = (String) lVar.a(reader);
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.k("extractedText", "extractedText", reader);
                    }
                    break;
                case 5:
                    str3 = (String) lVar.a(reader);
                    if (str3 == null) {
                        throw com.squareup.moshi.internal.b.k("createdAt", "createdAt", reader);
                    }
                    break;
            }
            l = l2;
        }
        Long l3 = l;
        reader.i();
        Boolean bool2 = bool;
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("uuid", "uuid", reader);
        }
        if (l3 == null) {
            throw com.squareup.moshi.internal.b.e("userId", "userId", reader);
        }
        long jLongValue = l3.longValue();
        if (list == null) {
            throw com.squareup.moshi.internal.b.e("artifactUuids", "artifactUuids", reader);
        }
        if (bool2 == null) {
            throw com.squareup.moshi.internal.b.e("isPrivate", "private", reader);
        }
        boolean zBooleanValue = bool2.booleanValue();
        if (str2 == null) {
            throw com.squareup.moshi.internal.b.e("extractedText", "extractedText", reader);
        }
        if (str3 != null) {
            return new MagicNotesResponse(str, jLongValue, list, zBooleanValue, str2, str3);
        }
        throw com.squareup.moshi.internal.b.e("createdAt", "createdAt", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        MagicNotesResponse magicNotesResponse = (MagicNotesResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (magicNotesResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("uuid");
        l lVar = this.b;
        lVar.g(writer, magicNotesResponse.a);
        writer.l("userId");
        this.c.g(writer, Long.valueOf(magicNotesResponse.b));
        writer.l("artifactUuids");
        this.d.g(writer, magicNotesResponse.c);
        writer.l("private");
        this.e.g(writer, Boolean.valueOf(magicNotesResponse.d));
        writer.l("extractedText");
        lVar.g(writer, magicNotesResponse.e);
        writer.l("createdAt");
        lVar.g(writer, magicNotesResponse.f);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(40, "GeneratedJsonAdapter(MagicNotesResponse)", "toString(...)");
    }
}
