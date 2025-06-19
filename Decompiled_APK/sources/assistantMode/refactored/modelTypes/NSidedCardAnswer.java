package assistantMode.refactored.modelTypes;

import androidx.compose.animation.d0;
import assistantMode.enums.EnumC1452f;
import assistantMode.enums.u;
import java.util.ArrayList;
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
public final class NSidedCardAnswer implements assistantMode.refactored.interfaces.c {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] h;
    public final EnumC1452f a;
    public final long b;
    public final long c;
    public final u d;
    public final long e;
    public final List f;
    public final List g;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return NSidedCardAnswer$$serializer.INSTANCE;
        }
    }

    static {
        P p = P.a;
        h = new KSerializer[]{null, null, null, null, null, new C5048d(p, 0), new C5048d(p, 0)};
    }

    public /* synthetic */ NSidedCardAnswer(int i, EnumC1452f enumC1452f, long j, long j2, u uVar, long j3, List list, List list2) {
        if (127 != (i & 127)) {
            AbstractC5047c0.k(i, 127, NSidedCardAnswer$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = enumC1452f;
        this.b = j;
        this.c = j2;
        this.d = uVar;
        this.e = j3;
        this.f = list;
        this.g = list2;
    }

    @Override // assistantMode.refactored.interfaces.c
    public final long a() {
        return this.e;
    }

    @Override // assistantMode.refactored.interfaces.c
    public final long b() {
        return this.c;
    }

    @Override // assistantMode.refactored.interfaces.c
    public final EnumC1452f c() {
        return this.a;
    }

    @Override // assistantMode.refactored.interfaces.c
    public final long d() {
        return this.b;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof NSidedCardAnswer)) {
            return false;
        }
        NSidedCardAnswer nSidedCardAnswer = (NSidedCardAnswer) obj;
        return this.a == nSidedCardAnswer.a && this.b == nSidedCardAnswer.b && this.c == nSidedCardAnswer.c && this.d == nSidedCardAnswer.d && this.e == nSidedCardAnswer.e && Intrinsics.b(this.f, nSidedCardAnswer.f) && Intrinsics.b(this.g, nSidedCardAnswer.g);
    }

    public final int hashCode() {
        return this.g.hashCode() + d0.f(d0.d((this.d.hashCode() + d0.d(d0.d(this.a.hashCode() * 31, 31, this.b), 31, this.c)) * 31, 31, this.e), 31, this.f);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("NSidedCardAnswer(correctness=");
        sb.append(this.a);
        sb.append(", round=");
        sb.append(this.b);
        sb.append(", studiableItemId=");
        sb.append(this.c);
        sb.append(", studyModeType=");
        sb.append(this.d);
        sb.append(", timestamp=");
        sb.append(this.e);
        sb.append(", promptSideIds=");
        sb.append(this.f);
        sb.append(", answerSideIds=");
        return android.support.v4.media.session.a.n(")", sb, this.g);
    }

    public NSidedCardAnswer(EnumC1452f correctness, long j, long j2, u studyModeType, long j3, ArrayList promptSideIds, ArrayList answerSideIds) {
        Intrinsics.checkNotNullParameter(correctness, "correctness");
        Intrinsics.checkNotNullParameter(studyModeType, "studyModeType");
        Intrinsics.checkNotNullParameter(promptSideIds, "promptSideIds");
        Intrinsics.checkNotNullParameter(answerSideIds, "answerSideIds");
        this.a = correctness;
        this.b = j;
        this.c = j2;
        this.d = studyModeType;
        this.e = j3;
        this.f = promptSideIds;
        this.g = answerSideIds;
    }
}
