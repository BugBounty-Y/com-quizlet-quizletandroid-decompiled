package assistantMode.refactored.modelTypes;

import androidx.compose.animation.d0;
import assistantMode.enums.EnumC1452f;
import assistantMode.enums.u;
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
public final class McqAnswer implements assistantMode.refactored.interfaces.c {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] g = {null, null, null, null, null, new C5048d(P.a, 0)};
    public final EnumC1452f a;
    public final long b;
    public final long c;
    public final u d;
    public final long e;
    public final List f;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return McqAnswer$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ McqAnswer(int i, EnumC1452f enumC1452f, long j, long j2, u uVar, long j3, List list) {
        if (63 != (i & 63)) {
            AbstractC5047c0.k(i, 63, McqAnswer$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = enumC1452f;
        this.b = j;
        this.c = j2;
        this.d = uVar;
        this.e = j3;
        this.f = list;
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
        if (!(obj instanceof McqAnswer)) {
            return false;
        }
        McqAnswer mcqAnswer = (McqAnswer) obj;
        return this.a == mcqAnswer.a && this.b == mcqAnswer.b && this.c == mcqAnswer.c && this.d == mcqAnswer.d && this.e == mcqAnswer.e && Intrinsics.b(this.f, mcqAnswer.f);
    }

    public final int hashCode() {
        return this.f.hashCode() + d0.d((this.d.hashCode() + d0.d(d0.d(this.a.hashCode() * 31, 31, this.b), 31, this.c)) * 31, 31, this.e);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("McqAnswer(correctness=");
        sb.append(this.a);
        sb.append(", round=");
        sb.append(this.b);
        sb.append(", studiableItemId=");
        sb.append(this.c);
        sb.append(", studyModeType=");
        sb.append(this.d);
        sb.append(", timestamp=");
        sb.append(this.e);
        sb.append(", selectedOptionIds=");
        return android.support.v4.media.session.a.n(")", sb, this.f);
    }
}
