package com.quizlet.remote.model.studiableitem;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.collections.Z;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RemoteCustomTextDistractorJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;

    public RemoteCustomTextDistractorJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("plainText", "languageCode", "ttsUrl", "ttsSlowUrl", "richText");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "plainText");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(String.class, m, "ttsUrl");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(String.class, Z.b(new b(0)), "richText");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        String str2 = null;
        String str3 = null;
        String str4 = null;
        String str5 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 != -1) {
                l lVar = this.b;
                if (iK0 == 0) {
                    str = (String) lVar.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("plainText", "plainText", reader);
                    }
                } else if (iK0 != 1) {
                    l lVar2 = this.c;
                    if (iK0 == 2) {
                        str3 = (String) lVar2.a(reader);
                    } else if (iK0 == 3) {
                        str4 = (String) lVar2.a(reader);
                    } else if (iK0 == 4) {
                        str5 = (String) this.d.a(reader);
                    }
                } else {
                    str2 = (String) lVar.a(reader);
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.k("languageCode", "languageCode", reader);
                    }
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("plainText", "plainText", reader);
        }
        if (str2 != null) {
            return new RemoteCustomTextDistractor(str, str2, str3, str4, str5);
        }
        throw com.squareup.moshi.internal.b.e("languageCode", "languageCode", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteCustomTextDistractor remoteCustomTextDistractor = (RemoteCustomTextDistractor) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteCustomTextDistractor == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("plainText");
        String str = remoteCustomTextDistractor.a;
        l lVar = this.b;
        lVar.g(writer, str);
        writer.l("languageCode");
        lVar.g(writer, remoteCustomTextDistractor.b);
        writer.l("ttsUrl");
        l lVar2 = this.c;
        lVar2.g(writer, remoteCustomTextDistractor.c);
        writer.l("ttsSlowUrl");
        lVar2.g(writer, remoteCustomTextDistractor.d);
        writer.l("richText");
        this.d.g(writer, remoteCustomTextDistractor.e);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(48, "GeneratedJsonAdapter(RemoteCustomTextDistractor)", "toString(...)");
    }
}
