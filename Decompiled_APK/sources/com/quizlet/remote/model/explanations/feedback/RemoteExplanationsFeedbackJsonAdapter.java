package com.quizlet.remote.model.explanations.feedback;

import com.airbnb.lottie.parser.moshi.c;
import com.amazon.device.ads.DtbDeviceData;
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
public final class RemoteExplanationsFeedbackJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;

    public RemoteExplanationsFeedbackJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("content_url", "screen_size", "feedbackContent");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "contentUrl");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(String.class, m, "feedbackContent");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        String str2 = null;
        String str3 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 != -1) {
                l lVar = this.b;
                if (iK0 == 0) {
                    str = (String) lVar.a(reader);
                    if (str == null) {
                        throw b.k("contentUrl", "content_url", reader);
                    }
                } else if (iK0 == 1) {
                    str2 = (String) lVar.a(reader);
                    if (str2 == null) {
                        throw b.k(DtbDeviceData.DEVICE_DATA_SCREEN_SIZE_KEY, "screen_size", reader);
                    }
                } else if (iK0 == 2) {
                    str3 = (String) this.c.a(reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        if (str == null) {
            throw b.e("contentUrl", "content_url", reader);
        }
        if (str2 != null) {
            return new RemoteExplanationsFeedback(str, str2, str3);
        }
        throw b.e(DtbDeviceData.DEVICE_DATA_SCREEN_SIZE_KEY, "screen_size", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteExplanationsFeedback remoteExplanationsFeedback = (RemoteExplanationsFeedback) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteExplanationsFeedback == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("content_url");
        l lVar = this.b;
        lVar.g(writer, remoteExplanationsFeedback.a);
        writer.l("screen_size");
        lVar.g(writer, remoteExplanationsFeedback.b);
        writer.l("feedbackContent");
        this.c.g(writer, remoteExplanationsFeedback.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(48, "GeneratedJsonAdapter(RemoteExplanationsFeedback)", "toString(...)");
    }
}
