package com.quizlet.remote.model.studiableitem;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
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
public final class RemoteCustomDistractorJsonAdapter extends l {
    public final c a;
    public final l b;

    public RemoteCustomDistractorJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("text");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(RemoteCustomTextDistractor.class, M.a, "text");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        RemoteCustomTextDistractor remoteCustomTextDistractor = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                remoteCustomTextDistractor = (RemoteCustomTextDistractor) this.b.a(reader);
            }
        }
        reader.i();
        return new RemoteCustomDistractor(remoteCustomTextDistractor);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteCustomDistractor remoteCustomDistractor = (RemoteCustomDistractor) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteCustomDistractor == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("text");
        this.b.g(writer, remoteCustomDistractor.a);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(44, "GeneratedJsonAdapter(RemoteCustomDistractor)", "toString(...)");
    }
}
