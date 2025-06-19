package com.quizlet.remote.model.achievements;

import androidx.compose.animation.d0;
import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class StreakResponse extends ApiResponse {
    public final StreakDataResponse d;

    @m(generateAdapter = true)
    @Metadata
    public static final class StreakDataResponse {
        public final String a;
        public final int b;
        public final long c;
        public final boolean d;
        public final long e;
        public final String f;
        public final String g;
        public final String h;
        public final BadgeImageUrlResponse i;
        public final String j;

        public StreakDataResponse(String progressType, int i, long j, boolean z, long j2, String status, String name, String description, BadgeImageUrlResponse imageUrl, String str) {
            Intrinsics.checkNotNullParameter(progressType, "progressType");
            Intrinsics.checkNotNullParameter(status, "status");
            Intrinsics.checkNotNullParameter(name, "name");
            Intrinsics.checkNotNullParameter(description, "description");
            Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
            this.a = progressType;
            this.b = i;
            this.c = j;
            this.d = z;
            this.e = j2;
            this.f = status;
            this.g = name;
            this.h = description;
            this.i = imageUrl;
            this.j = str;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof StreakDataResponse)) {
                return false;
            }
            StreakDataResponse streakDataResponse = (StreakDataResponse) obj;
            return Intrinsics.b(this.a, streakDataResponse.a) && this.b == streakDataResponse.b && this.c == streakDataResponse.c && this.d == streakDataResponse.d && this.e == streakDataResponse.e && Intrinsics.b(this.f, streakDataResponse.f) && Intrinsics.b(this.g, streakDataResponse.g) && Intrinsics.b(this.h, streakDataResponse.h) && Intrinsics.b(this.i, streakDataResponse.i) && Intrinsics.b(this.j, streakDataResponse.j);
        }

        public final int hashCode() {
            int iHashCode = (this.i.hashCode() + d0.e(d0.e(d0.e(d0.d(d0.g(d0.d(d0.b(this.b, this.a.hashCode() * 31, 31), 31, this.c), 31, this.d), 31, this.e), 31, this.f), 31, this.g), 31, this.h)) * 31;
            String str = this.j;
            return iHashCode + (str == null ? 0 : str.hashCode());
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("StreakDataResponse(progressType=");
            sb.append(this.a);
            sb.append(", count=");
            sb.append(this.b);
            sb.append(", expirationDate=");
            sb.append(this.c);
            sb.append(", hasShownModal=");
            sb.append(this.d);
            sb.append(", startDate=");
            sb.append(this.e);
            sb.append(", status=");
            sb.append(this.f);
            sb.append(", name=");
            sb.append(this.g);
            sb.append(", description=");
            sb.append(this.h);
            sb.append(", imageUrl=");
            sb.append(this.i);
            sb.append(", goalTextAlignment=");
            return android.support.v4.media.session.a.t(sb, this.j, ")");
        }
    }

    public StreakResponse(StreakDataResponse streakDataResponse) {
        this.d = streakDataResponse;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof StreakResponse) && Intrinsics.b(this.d, ((StreakResponse) obj).d);
    }

    public final int hashCode() {
        StreakDataResponse streakDataResponse = this.d;
        if (streakDataResponse == null) {
            return 0;
        }
        return streakDataResponse.hashCode();
    }

    public final String toString() {
        return "StreakResponse(data=" + this.d + ")";
    }
}
