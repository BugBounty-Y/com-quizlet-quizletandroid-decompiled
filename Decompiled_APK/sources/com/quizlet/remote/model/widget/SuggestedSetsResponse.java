package com.quizlet.remote.model.widget;

import androidx.compose.animation.d0;
import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class SuggestedSetsResponse extends ApiResponse {
    public final Data d;

    @m(generateAdapter = true)
    @Metadata
    public static final class Data {
        public final StreakData a;
        public final List b;

        public Data(StreakData streakData, List setData) {
            Intrinsics.checkNotNullParameter(streakData, "streakData");
            Intrinsics.checkNotNullParameter(setData, "setData");
            this.a = streakData;
            this.b = setData;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Data)) {
                return false;
            }
            Data data = (Data) obj;
            return Intrinsics.b(this.a, data.a) && Intrinsics.b(this.b, data.b);
        }

        public final int hashCode() {
            return this.b.hashCode() + (this.a.hashCode() * 31);
        }

        public final String toString() {
            return "Data(streakData=" + this.a + ", setData=" + this.b + ")";
        }
    }

    @m(generateAdapter = true)
    @Metadata
    public static final class MemoryScore {
        public final int a;
        public final int b;
        public final String c;

        public MemoryScore(int i, int i2, String label) {
            Intrinsics.checkNotNullParameter(label, "label");
            this.a = i;
            this.b = i2;
            this.c = label;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof MemoryScore)) {
                return false;
            }
            MemoryScore memoryScore = (MemoryScore) obj;
            return this.a == memoryScore.a && this.b == memoryScore.b && Intrinsics.b(this.c, memoryScore.c);
        }

        public final int hashCode() {
            return this.c.hashCode() + d0.b(this.b, Integer.hashCode(this.a) * 31, 31);
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("MemoryScore(delay=");
            sb.append(this.a);
            sb.append(", score=");
            sb.append(this.b);
            sb.append(", label=");
            return android.support.v4.media.session.a.t(sb, this.c, ")");
        }
    }

    @m(generateAdapter = true)
    @Metadata
    public static final class SetData {
        public final long a;
        public final String b;
        public final int c;
        public final int d;
        public final int e;
        public final int f;
        public final List g;

        public SetData(long j, String title, int i, int i2, int i3, int i4, List list) {
            Intrinsics.checkNotNullParameter(title, "title");
            this.a = j;
            this.b = title;
            this.c = i;
            this.d = i2;
            this.e = i3;
            this.f = i4;
            this.g = list;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof SetData)) {
                return false;
            }
            SetData setData = (SetData) obj;
            return this.a == setData.a && Intrinsics.b(this.b, setData.b) && this.c == setData.c && this.d == setData.d && this.e == setData.e && this.f == setData.f && Intrinsics.b(this.g, setData.g);
        }

        public final int hashCode() {
            int iB = d0.b(this.f, d0.b(this.e, d0.b(this.d, d0.b(this.c, d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31), 31), 31), 31);
            List list = this.g;
            return iB + (list == null ? 0 : list.hashCode());
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("SetData(id=");
            sb.append(this.a);
            sb.append(", title=");
            sb.append(this.b);
            sb.append(", count=");
            sb.append(this.c);
            sb.append(", itemsKnown=");
            sb.append(this.d);
            sb.append(", itemsStillLearning=");
            sb.append(this.e);
            sb.append(", itemsRemaining=");
            sb.append(this.f);
            sb.append(", memoryScores=");
            return android.support.v4.media.session.a.n(")", sb, this.g);
        }
    }

    @m(generateAdapter = true)
    @Metadata
    public static final class StreakData {
        public final Integer a;
        public final String b;
        public final Long c;

        public StreakData(Integer num, String str, Long l) {
            this.a = num;
            this.b = str;
            this.c = l;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof StreakData)) {
                return false;
            }
            StreakData streakData = (StreakData) obj;
            return Intrinsics.b(this.a, streakData.a) && Intrinsics.b(this.b, streakData.b) && Intrinsics.b(this.c, streakData.c);
        }

        public final int hashCode() {
            Integer num = this.a;
            int iHashCode = (num == null ? 0 : num.hashCode()) * 31;
            String str = this.b;
            int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
            Long l = this.c;
            return iHashCode2 + (l != null ? l.hashCode() : 0);
        }

        public final String toString() {
            return "StreakData(length=" + this.a + ", progressType=" + this.b + ", lastHistoryDate=" + this.c + ")";
        }
    }

    public SuggestedSetsResponse(Data data) {
        this.d = data;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof SuggestedSetsResponse) && Intrinsics.b(this.d, ((SuggestedSetsResponse) obj).d);
    }

    public final int hashCode() {
        Data data = this.d;
        if (data == null) {
            return 0;
        }
        return data.hashCode();
    }

    public final String toString() {
        return "SuggestedSetsResponse(data=" + this.d + ")";
    }
}
