package com.quizlet.remote.model.grading;

import com.airbnb.lottie.parser.moshi.c;
import com.amazon.device.ads.DtbDeviceData;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
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
public final class RemoteLongTextGradingResultJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;

    public RemoteLongTextGradingResultJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("grade", DBSessionFields.Names.SCORE, DtbDeviceData.DEVICE_DATA_MODEL_KEY, "cnn_score", "missing");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "grade");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Double.class, m, DBSessionFields.Names.SCORE);
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(String.class, m, DtbDeviceData.DEVICE_DATA_MODEL_KEY);
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        Double d = null;
        String str2 = null;
        Double d2 = null;
        String str3 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 != 0) {
                l lVar = this.c;
                if (iK0 != 1) {
                    l lVar2 = this.d;
                    if (iK0 == 2) {
                        str2 = (String) lVar2.a(reader);
                    } else if (iK0 == 3) {
                        d2 = (Double) lVar.a(reader);
                    } else if (iK0 == 4) {
                        str3 = (String) lVar2.a(reader);
                    }
                } else {
                    d = (Double) lVar.a(reader);
                }
            } else {
                str = (String) this.b.a(reader);
                if (str == null) {
                    throw b.k("grade", "grade", reader);
                }
            }
        }
        reader.i();
        if (str != null) {
            return new RemoteLongTextGradingResult(str, d, str2, d2, str3);
        }
        throw b.e("grade", "grade", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteLongTextGradingResult remoteLongTextGradingResult = (RemoteLongTextGradingResult) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteLongTextGradingResult == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("grade");
        this.b.g(writer, remoteLongTextGradingResult.a);
        writer.l(DBSessionFields.Names.SCORE);
        l lVar = this.c;
        lVar.g(writer, remoteLongTextGradingResult.b);
        writer.l(DtbDeviceData.DEVICE_DATA_MODEL_KEY);
        l lVar2 = this.d;
        lVar2.g(writer, remoteLongTextGradingResult.c);
        writer.l("cnn_score");
        lVar.g(writer, remoteLongTextGradingResult.d);
        writer.l("missing");
        lVar2.g(writer, remoteLongTextGradingResult.e);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(49, "GeneratedJsonAdapter(RemoteLongTextGradingResult)", "toString(...)");
    }
}
