package com.quizlet.remote.model.explanations.solution;

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
public final class RemoteSolutionColumnJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;

    public RemoteSolutionColumnJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("text", "hasInvalidKatex", "images");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "text");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Boolean.TYPE, m, "hasInvalidKatex");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(RemoteSolutionColumnImages.class, m, "images");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        Boolean bool = null;
        RemoteSolutionColumnImages remoteSolutionColumnImages = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                str = (String) this.b.a(reader);
                if (str == null) {
                    throw b.k("text", "text", reader);
                }
            } else if (iK0 == 1) {
                bool = (Boolean) this.c.a(reader);
                if (bool == null) {
                    throw b.k("hasInvalidKatex", "hasInvalidKatex", reader);
                }
            } else if (iK0 == 2 && (remoteSolutionColumnImages = (RemoteSolutionColumnImages) this.d.a(reader)) == null) {
                throw b.k("images", "images", reader);
            }
        }
        reader.i();
        if (str == null) {
            throw b.e("text", "text", reader);
        }
        if (bool == null) {
            throw b.e("hasInvalidKatex", "hasInvalidKatex", reader);
        }
        boolean zBooleanValue = bool.booleanValue();
        if (remoteSolutionColumnImages != null) {
            return new RemoteSolutionColumn(str, zBooleanValue, remoteSolutionColumnImages);
        }
        throw b.e("images", "images", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteSolutionColumn remoteSolutionColumn = (RemoteSolutionColumn) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteSolutionColumn == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("text");
        this.b.g(writer, remoteSolutionColumn.a);
        writer.l("hasInvalidKatex");
        this.c.g(writer, Boolean.valueOf(remoteSolutionColumn.b));
        writer.l("images");
        this.d.g(writer, remoteSolutionColumn.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(42, "GeneratedJsonAdapter(RemoteSolutionColumn)", "toString(...)");
    }
}
