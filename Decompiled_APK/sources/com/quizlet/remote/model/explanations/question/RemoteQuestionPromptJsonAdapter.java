package com.quizlet.remote.model.explanations.question;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.explanations.RemoteSimpleImage;
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
public final class RemoteQuestionPromptJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;

    public RemoteQuestionPromptJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("text", "image");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "text");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(RemoteSimpleImage.class, m, "image");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        RemoteSimpleImage remoteSimpleImage = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                str = (String) this.b.a(reader);
            } else if (iK0 == 1) {
                remoteSimpleImage = (RemoteSimpleImage) this.c.a(reader);
            }
        }
        reader.i();
        return new RemoteQuestionPrompt(str, remoteSimpleImage);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteQuestionPrompt remoteQuestionPrompt = (RemoteQuestionPrompt) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteQuestionPrompt == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("text");
        this.b.g(writer, remoteQuestionPrompt.a);
        writer.l("image");
        this.c.g(writer, remoteQuestionPrompt.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(42, "GeneratedJsonAdapter(RemoteQuestionPrompt)", "toString(...)");
    }
}
