package assistantMode.types.test;

import androidx.compose.animation.d0;
import assistantMode.enums.j;
import assistantMode.enums.l;
import com.google.android.gms.ads.g;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import kotlinx.serialization.internal.P;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes.dex */
public final class TestSettings {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] m;
    public final List a;
    public final List b;
    public final List c;
    public final int d;
    public final Boolean e;
    public final Boolean f;
    public final Boolean g;
    public final List h;
    public final List i;
    public final List j;
    public final List k;
    public final List l;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return TestSettings$$serializer.INSTANCE;
        }
    }

    static {
        C5048d c5048d = new C5048d(j.f, 0);
        l lVar = l.f;
        C5048d c5048d2 = new C5048d(lVar, 0);
        C5048d c5048d3 = new C5048d(lVar, 0);
        P p = P.a;
        m = new KSerializer[]{c5048d, c5048d2, c5048d3, null, null, null, null, new C5048d(p, 0), new C5048d(p, 0), new C5048d(p, 0), new C5048d(p, 0), new C5048d(p, 0)};
    }

    public /* synthetic */ TestSettings(int i, List list, List list2, List list3, int i2, Boolean bool, Boolean bool2, Boolean bool3, List list4, List list5, List list6, List list7, List list8) {
        if (15 != (i & 15)) {
            AbstractC5047c0.k(i, 15, TestSettings$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = list;
        this.b = list2;
        this.c = list3;
        this.d = i2;
        if ((i & 16) == 0) {
            this.e = Boolean.FALSE;
        } else {
            this.e = bool;
        }
        if ((i & 32) == 0) {
            this.f = Boolean.FALSE;
        } else {
            this.f = bool2;
        }
        if ((i & 64) == 0) {
            this.g = Boolean.FALSE;
        } else {
            this.g = bool3;
        }
        if ((i & 128) == 0) {
            this.h = null;
        } else {
            this.h = list4;
        }
        if ((i & 256) == 0) {
            this.i = null;
        } else {
            this.i = list5;
        }
        if ((i & g.MAX_CONTENT_URL_LENGTH) == 0) {
            this.j = null;
        } else {
            this.j = list6;
        }
        if ((i & 1024) == 0) {
            this.k = null;
        } else {
            this.k = list7;
        }
        if ((i & 2048) == 0) {
            this.l = null;
        } else {
            this.l = list8;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof TestSettings)) {
            return false;
        }
        TestSettings testSettings = (TestSettings) obj;
        return Intrinsics.b(this.a, testSettings.a) && Intrinsics.b(this.b, testSettings.b) && Intrinsics.b(this.c, testSettings.c) && this.d == testSettings.d && Intrinsics.b(this.e, testSettings.e) && Intrinsics.b(this.f, testSettings.f) && Intrinsics.b(this.g, testSettings.g) && Intrinsics.b(this.h, testSettings.h) && Intrinsics.b(this.i, testSettings.i) && Intrinsics.b(this.j, testSettings.j) && Intrinsics.b(this.k, testSettings.k) && Intrinsics.b(this.l, testSettings.l);
    }

    public final int hashCode() {
        int iB = d0.b(this.d, d0.f(d0.f(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31);
        Boolean bool = this.e;
        int iHashCode = (iB + (bool == null ? 0 : bool.hashCode())) * 31;
        Boolean bool2 = this.f;
        int iHashCode2 = (iHashCode + (bool2 == null ? 0 : bool2.hashCode())) * 31;
        Boolean bool3 = this.g;
        int iHashCode3 = (iHashCode2 + (bool3 == null ? 0 : bool3.hashCode())) * 31;
        List list = this.h;
        int iHashCode4 = (iHashCode3 + (list == null ? 0 : list.hashCode())) * 31;
        List list2 = this.i;
        int iHashCode5 = (iHashCode4 + (list2 == null ? 0 : list2.hashCode())) * 31;
        List list3 = this.j;
        int iHashCode6 = (iHashCode5 + (list3 == null ? 0 : list3.hashCode())) * 31;
        List list4 = this.k;
        int iHashCode7 = (iHashCode6 + (list4 == null ? 0 : list4.hashCode())) * 31;
        List list5 = this.l;
        return iHashCode7 + (list5 != null ? list5.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TestSettings(enabledQuestionTypes=");
        sb.append(this.a);
        sb.append(", enabledPromptSides=");
        sb.append(this.b);
        sb.append(", enabledAnswerSides=");
        sb.append(this.c);
        sb.append(", numQuestions=");
        sb.append(this.d);
        sb.append(", includeStarredItems=");
        sb.append(this.e);
        sb.append(", useMissedAndUnstudied=");
        sb.append(this.f);
        sb.append(", shouldOrderTestQuestions=");
        sb.append(this.g);
        sb.append(", studiableItemIds=");
        sb.append(this.h);
        sb.append(", starredStudiableItemIds=");
        sb.append(this.i);
        sb.append(", correctStudiableIds=");
        sb.append(this.j);
        sb.append(", missedStudiableIds=");
        sb.append(this.k);
        sb.append(", unstudiedItemIds=");
        return android.support.v4.media.session.a.n(")", sb, this.l);
    }

    public TestSettings(List enabledQuestionTypes, List enabledPromptSides, List enabledAnswerSides, int i, Boolean bool, Boolean bool2, Boolean bool3, List list, List list2, List list3, List list4, List list5) {
        Intrinsics.checkNotNullParameter(enabledQuestionTypes, "enabledQuestionTypes");
        Intrinsics.checkNotNullParameter(enabledPromptSides, "enabledPromptSides");
        Intrinsics.checkNotNullParameter(enabledAnswerSides, "enabledAnswerSides");
        this.a = enabledQuestionTypes;
        this.b = enabledPromptSides;
        this.c = enabledAnswerSides;
        this.d = i;
        this.e = bool;
        this.f = bool2;
        this.g = bool3;
        this.h = list;
        this.i = list2;
        this.j = list3;
        this.k = list4;
        this.l = list5;
    }
}
