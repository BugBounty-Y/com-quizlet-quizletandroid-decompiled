package com.quizlet.remote.model.grading;

import android.support.v4.media.session.a;
import com.amazon.device.ads.DtbDeviceData;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteLongTextGradingResult {
    public final String a;
    public final Double b;
    public final String c;
    public final Double d;
    public final String e;

    public RemoteLongTextGradingResult(@InterfaceC4853h(name = "grade") @NotNull String grade, @InterfaceC4853h(name = DBSessionFields.Names.SCORE) Double d, @InterfaceC4853h(name = DtbDeviceData.DEVICE_DATA_MODEL_KEY) String str, @InterfaceC4853h(name = "cnn_score") Double d2, @InterfaceC4853h(name = "missing") String str2) {
        Intrinsics.checkNotNullParameter(grade, "grade");
        this.a = grade;
        this.b = d;
        this.c = str;
        this.d = d2;
        this.e = str2;
    }

    @NotNull
    public final RemoteLongTextGradingResult copy(@InterfaceC4853h(name = "grade") @NotNull String grade, @InterfaceC4853h(name = DBSessionFields.Names.SCORE) Double d, @InterfaceC4853h(name = DtbDeviceData.DEVICE_DATA_MODEL_KEY) String str, @InterfaceC4853h(name = "cnn_score") Double d2, @InterfaceC4853h(name = "missing") String str2) {
        Intrinsics.checkNotNullParameter(grade, "grade");
        return new RemoteLongTextGradingResult(grade, d, str, d2, str2);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteLongTextGradingResult)) {
            return false;
        }
        RemoteLongTextGradingResult remoteLongTextGradingResult = (RemoteLongTextGradingResult) obj;
        return Intrinsics.b(this.a, remoteLongTextGradingResult.a) && Intrinsics.b(this.b, remoteLongTextGradingResult.b) && Intrinsics.b(this.c, remoteLongTextGradingResult.c) && Intrinsics.b(this.d, remoteLongTextGradingResult.d) && Intrinsics.b(this.e, remoteLongTextGradingResult.e);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        Double d = this.b;
        int iHashCode2 = (iHashCode + (d == null ? 0 : d.hashCode())) * 31;
        String str = this.c;
        int iHashCode3 = (iHashCode2 + (str == null ? 0 : str.hashCode())) * 31;
        Double d2 = this.d;
        int iHashCode4 = (iHashCode3 + (d2 == null ? 0 : d2.hashCode())) * 31;
        String str2 = this.e;
        return iHashCode4 + (str2 != null ? str2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteLongTextGradingResult(grade=");
        sb.append(this.a);
        sb.append(", score=");
        sb.append(this.b);
        sb.append(", model=");
        sb.append(this.c);
        sb.append(", cnnScore=");
        sb.append(this.d);
        sb.append(", missing=");
        return a.t(sb, this.e, ")");
    }
}
