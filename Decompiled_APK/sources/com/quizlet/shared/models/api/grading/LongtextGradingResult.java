package com.quizlet.shared.models.api.grading;

import android.support.v4.media.session.a;
import androidx.compose.animation.d0;
import com.quizlet.shared.enums.l;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class LongtextGradingResult {

    @NotNull
    public static final Companion Companion = new Companion();
    public final l a;
    public final double b;
    public final String c;
    public final Double d;
    public final String e;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return LongtextGradingResult$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ LongtextGradingResult(int i, l lVar, double d, String str, Double d2, String str2) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, LongtextGradingResult$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = lVar;
        this.b = d;
        this.c = str;
        if ((i & 8) == 0) {
            this.d = null;
        } else {
            this.d = d2;
        }
        if ((i & 16) == 0) {
            this.e = null;
        } else {
            this.e = str2;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof LongtextGradingResult)) {
            return false;
        }
        LongtextGradingResult longtextGradingResult = (LongtextGradingResult) obj;
        return this.a == longtextGradingResult.a && Double.compare(this.b, longtextGradingResult.b) == 0 && Intrinsics.b(this.c, longtextGradingResult.c) && Intrinsics.b(this.d, longtextGradingResult.d) && Intrinsics.b(this.e, longtextGradingResult.e);
    }

    public final int hashCode() {
        int iE = d0.e(d0.a(this.b, this.a.hashCode() * 31, 31), 31, this.c);
        Double d = this.d;
        int iHashCode = (iE + (d == null ? 0 : d.hashCode())) * 31;
        String str = this.e;
        return iHashCode + (str != null ? str.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("LongtextGradingResult(grade=");
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
