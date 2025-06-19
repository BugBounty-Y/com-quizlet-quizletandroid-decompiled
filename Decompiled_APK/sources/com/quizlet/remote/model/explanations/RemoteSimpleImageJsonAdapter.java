package com.quizlet.remote.model.explanations;

import com.airbnb.lottie.parser.moshi.c;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
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
public final class RemoteSimpleImageJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;

    public RemoteSimpleImageJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("srcUrl", OTUXParamsKeys.OT_UX_HEIGHT, OTUXParamsKeys.OT_UX_WIDTH);
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "srcUrl");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Integer.class, m, OTUXParamsKeys.OT_UX_HEIGHT);
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
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
                l lVar = this.c;
                if (iK0 == 1) {
                    num = (Integer) lVar.a(reader);
                } else if (iK0 == 2) {
                    num2 = (Integer) lVar.a(reader);
                }
            } else {
                str = (String) this.b.a(reader);
                if (str == null) {
                    throw b.k("srcUrl", "srcUrl", reader);
                }
            }
        }
        reader.i();
        if (str != null) {
            return new RemoteSimpleImage(str, num, num2);
        }
        throw b.e("srcUrl", "srcUrl", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteSimpleImage remoteSimpleImage = (RemoteSimpleImage) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteSimpleImage == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("srcUrl");
        this.b.g(writer, remoteSimpleImage.a);
        writer.l(OTUXParamsKeys.OT_UX_HEIGHT);
        l lVar = this.c;
        lVar.g(writer, remoteSimpleImage.b);
        writer.l(OTUXParamsKeys.OT_UX_WIDTH);
        lVar.g(writer, remoteSimpleImage.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(39, "GeneratedJsonAdapter(RemoteSimpleImage)", "toString(...)");
    }
}
