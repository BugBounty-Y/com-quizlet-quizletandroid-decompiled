package com.quizlet.remote.model.explanations.solution;

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
public final class RemoteSolutionColumnImagesJsonAdapter extends l {
    public final c a;
    public final l b;

    public RemoteSolutionColumnImagesJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("latex", "additional");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(RemoteSolutionColumnImage.class, M.a, "latex");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        RemoteSolutionColumnImage remoteSolutionColumnImage = null;
        RemoteSolutionColumnImage remoteSolutionColumnImage2 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 != -1) {
                l lVar = this.b;
                if (iK0 == 0) {
                    remoteSolutionColumnImage = (RemoteSolutionColumnImage) lVar.a(reader);
                } else if (iK0 == 1) {
                    remoteSolutionColumnImage2 = (RemoteSolutionColumnImage) lVar.a(reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        return new RemoteSolutionColumnImages(remoteSolutionColumnImage, remoteSolutionColumnImage2);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteSolutionColumnImages remoteSolutionColumnImages = (RemoteSolutionColumnImages) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteSolutionColumnImages == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("latex");
        l lVar = this.b;
        lVar.g(writer, remoteSolutionColumnImages.a);
        writer.l("additional");
        lVar.g(writer, remoteSolutionColumnImages.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(48, "GeneratedJsonAdapter(RemoteSolutionColumnImages)", "toString(...)");
    }
}
