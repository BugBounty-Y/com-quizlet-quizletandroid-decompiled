package com.quizlet.data.model;

import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class SimpleImageJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;

    public SimpleImageJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("srcUrl", OTUXParamsKeys.OT_UX_HEIGHT, OTUXParamsKeys.OT_UX_WIDTH);
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        kotlin.collections.M m = kotlin.collections.M.a;
        com.squareup.moshi.l lVarA = moshi.a(String.class, m, "srcUrl");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(Integer.class, m, OTUXParamsKeys.OT_UX_HEIGHT);
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        Integer num = null;
        Integer num2 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 != 0) {
                com.squareup.moshi.l lVar = this.c;
                if (iK0 == 1) {
                    num = (Integer) lVar.a(reader);
                } else if (iK0 == 2) {
                    num2 = (Integer) lVar.a(reader);
                }
            } else {
                str = (String) this.b.a(reader);
                if (str == null) {
                    throw com.squareup.moshi.internal.b.k("srcUrl", "srcUrl", reader);
                }
            }
        }
        reader.i();
        if (str != null) {
            return new SimpleImage(str, num, num2);
        }
        throw com.squareup.moshi.internal.b.e("srcUrl", "srcUrl", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        SimpleImage simpleImage = (SimpleImage) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (simpleImage == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("srcUrl");
        this.b.g(writer, simpleImage.a);
        writer.l(OTUXParamsKeys.OT_UX_HEIGHT);
        com.squareup.moshi.l lVar = this.c;
        lVar.g(writer, simpleImage.b);
        writer.l(OTUXParamsKeys.OT_UX_WIDTH);
        lVar.g(writer, simpleImage.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(33, "GeneratedJsonAdapter(SimpleImage)", "toString(...)");
    }
}
