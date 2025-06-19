package com.quizlet.remote.model.practicetests;

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
public final class RemoteUpdateQuestionUuidJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;

    public RemoteUpdateQuestionUuidJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("questionUuid");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(String.class, M.a, "questionUuid");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0 && (str = (String) this.b.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("questionUuid", "questionUuid", reader);
            }
        }
        reader.i();
        if (str != null) {
            return new RemoteUpdateQuestionUuid(str);
        }
        throw com.squareup.moshi.internal.b.e("questionUuid", "questionUuid", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteUpdateQuestionUuid remoteUpdateQuestionUuid = (RemoteUpdateQuestionUuid) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteUpdateQuestionUuid == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("questionUuid");
        this.b.g(writer, remoteUpdateQuestionUuid.a);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(46, "GeneratedJsonAdapter(RemoteUpdateQuestionUuid)", "toString(...)");
    }
}
