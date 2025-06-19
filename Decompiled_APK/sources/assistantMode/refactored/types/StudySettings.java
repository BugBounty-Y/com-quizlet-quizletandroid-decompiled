package assistantMode.refactored.types;

import androidx.compose.animation.d0;
import assistantMode.enums.C;
import assistantMode.enums.j;
import assistantMode.enums.l;
import assistantMode.enums.w;
import assistantMode.enums.y;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class StudySettings {

    @NotNull
    public static final Companion Companion = new Companion();
    public final y a;
    public final NSidedCardSettings b;
    public final boolean c;
    public final w d;
    public final C e;
    public final String f;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return StudySettings$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ StudySettings(int i, y yVar, NSidedCardSettings nSidedCardSettings, boolean z, w wVar, C c, String str) {
        if (63 != (i & 63)) {
            AbstractC5047c0.k(i, 63, StudySettings$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = yVar;
        this.b = nSidedCardSettings;
        this.c = z;
        this.d = wVar;
        this.e = c;
        this.f = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudySettings)) {
            return false;
        }
        StudySettings studySettings = (StudySettings) obj;
        return this.a == studySettings.a && Intrinsics.b(this.b, studySettings.b) && this.c == studySettings.c && this.d == studySettings.d && this.e == studySettings.e && Intrinsics.b(this.f, studySettings.f);
    }

    public final int hashCode() {
        y yVar = this.a;
        int iG = d0.g((this.b.hashCode() + ((yVar == null ? 0 : yVar.hashCode()) * 31)) * 31, 31, this.c);
        w wVar = this.d;
        int iHashCode = (iG + (wVar == null ? 0 : wVar.hashCode())) * 31;
        C c = this.e;
        return this.f.hashCode() + ((iHashCode + (c != null ? c.hashCode() : 0)) * 31);
    }

    public final String toString() {
        return "StudySettings(knowledgeLevel=" + this.a + ", nSidedCardSettings=" + this.b + ", shuffle=" + this.c + ", studyPathGoal=" + this.d + ", taskSequence=" + this.e + ", userLanguageCode=" + this.f + ")";
    }

    public StudySettings(y yVar, NSidedCardSettings nSidedCardSettings, boolean z, w wVar, C c, String userLanguageCode) {
        Intrinsics.checkNotNullParameter(nSidedCardSettings, "nSidedCardSettings");
        Intrinsics.checkNotNullParameter(userLanguageCode, "userLanguageCode");
        this.a = yVar;
        this.b = nSidedCardSettings;
        this.c = z;
        this.d = wVar;
        this.e = c;
        this.f = userLanguageCode;
    }

    @kotlinx.serialization.f
    @Metadata
    public static final class NSidedCardSettings {

        @NotNull
        public static final Companion Companion = new Companion();
        public static final KSerializer[] f;
        public final List a;
        public final List b;
        public final List c;
        public final List d;
        public final List e;

        @Metadata
        public static final class Companion {
            @NotNull
            public final KSerializer serializer() {
                return StudySettings$NSidedCardSettings$$serializer.INSTANCE;
            }
        }

        static {
            j jVar = j.f;
            C5048d c5048d = new C5048d(jVar, 0);
            l lVar = l.f;
            f = new KSerializer[]{c5048d, new C5048d(lVar, 0), new C5048d(lVar, 0), new C5048d(lVar, 0), new C5048d(jVar, 0)};
        }

        public NSidedCardSettings(int i, List list, List list2, List list3, List list4, List list5) {
            if (15 != (i & 15)) {
                AbstractC5047c0.k(i, 15, StudySettings$NSidedCardSettings$$serializer.INSTANCE.getDescriptor());
                throw null;
            }
            this.a = list;
            this.b = list2;
            this.c = list3;
            this.d = list4;
            if ((i & 16) == 0) {
                this.e = assistantMode.a.a;
            } else {
                this.e = list5;
            }
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof NSidedCardSettings)) {
                return false;
            }
            NSidedCardSettings nSidedCardSettings = (NSidedCardSettings) obj;
            return Intrinsics.b(this.a, nSidedCardSettings.a) && Intrinsics.b(this.b, nSidedCardSettings.b) && Intrinsics.b(this.c, nSidedCardSettings.c) && Intrinsics.b(this.d, nSidedCardSettings.d) && Intrinsics.b(this.e, nSidedCardSettings.e);
        }

        public final int hashCode() {
            return this.e.hashCode() + d0.f(d0.f(d0.f(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d);
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("NSidedCardSettings(enabledQuestionTypes=");
            sb.append(this.a);
            sb.append(", enabledPromptSides=");
            sb.append(this.b);
            sb.append(", enabledAnswerSides=");
            sb.append(this.c);
            sb.append(", enabledWrittenAnswerSides=");
            sb.append(this.d);
            sb.append(", enabledLocationQuestionTypes=");
            return android.support.v4.media.session.a.n(")", sb, this.e);
        }

        public NSidedCardSettings(List enabledQuestionTypes, List enabledPromptSides, List enabledAnswerSides, ArrayList enabledWrittenAnswerSides, List enabledLocationQuestionTypes) {
            Intrinsics.checkNotNullParameter(enabledQuestionTypes, "enabledQuestionTypes");
            Intrinsics.checkNotNullParameter(enabledPromptSides, "enabledPromptSides");
            Intrinsics.checkNotNullParameter(enabledAnswerSides, "enabledAnswerSides");
            Intrinsics.checkNotNullParameter(enabledWrittenAnswerSides, "enabledWrittenAnswerSides");
            Intrinsics.checkNotNullParameter(enabledLocationQuestionTypes, "enabledLocationQuestionTypes");
            this.a = enabledQuestionTypes;
            this.b = enabledPromptSides;
            this.c = enabledAnswerSides;
            this.d = enabledWrittenAnswerSides;
            this.e = enabledLocationQuestionTypes;
        }
    }
}
