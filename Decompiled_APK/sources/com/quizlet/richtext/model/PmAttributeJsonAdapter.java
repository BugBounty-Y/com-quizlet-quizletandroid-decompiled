package com.quizlet.richtext.model;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.base.AssociationNames;
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
public final class PmAttributeJsonAdapter extends l {
    public final c a;
    public final l b;

    public PmAttributeJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b(AssociationNames.CLASS);
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(String.class, M.a, "pmClass");
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
                throw b.k("pmClass", AssociationNames.CLASS, reader);
            }
        }
        reader.i();
        if (str != null) {
            return new PmAttribute(str);
        }
        throw b.e("pmClass", AssociationNames.CLASS, reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        PmAttribute pmAttribute = (PmAttribute) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (pmAttribute == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l(AssociationNames.CLASS);
        this.b.g(writer, pmAttribute.a);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(33, "GeneratedJsonAdapter(PmAttribute)", "toString(...)");
    }
}
