package assistantMode.refactored.types;

import androidx.compose.animation.d0;
import assistantMode.enums.o;
import assistantMode.refactored.enums.j;
import assistantMode.refactored.enums.l;
import assistantMode.types.QuestionElement;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class AlternativeQuestion implements f {

    @NotNull
    public static final Companion Companion = new Companion();
    public final long a;
    public final l b;
    public final long c;
    public final j d;
    public final String e;
    public final long f;
    public final o g;
    public final int h;
    public final QuestionElement i;
    public final QuestionElement j;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return AlternativeQuestion$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ AlternativeQuestion(int i, long j, l lVar, long j2, j jVar, String str, long j3, o oVar, int i2, QuestionElement questionElement, QuestionElement questionElement2) {
        if (1023 != (i & 1023)) {
            AbstractC5047c0.k(i, 1023, AlternativeQuestion$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = j;
        this.b = lVar;
        this.c = j2;
        this.d = jVar;
        this.e = str;
        this.f = j3;
        this.g = oVar;
        this.h = i2;
        this.i = questionElement;
        this.j = questionElement2;
    }

    @Override // assistantMode.refactored.types.f
    public final long a() {
        return this.f;
    }

    @Override // assistantMode.refactored.types.f
    public final long b() {
        return this.a;
    }

    @Override // assistantMode.refactored.types.f
    public final String c() {
        return this.e;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof AlternativeQuestion)) {
            return false;
        }
        AlternativeQuestion alternativeQuestion = (AlternativeQuestion) obj;
        return this.a == alternativeQuestion.a && this.b == alternativeQuestion.b && this.c == alternativeQuestion.c && this.d == alternativeQuestion.d && Intrinsics.b(this.e, alternativeQuestion.e) && this.f == alternativeQuestion.f && this.g == alternativeQuestion.g && this.h == alternativeQuestion.h && Intrinsics.b(this.i, alternativeQuestion.i) && Intrinsics.b(this.j, alternativeQuestion.j);
    }

    public final int hashCode() {
        return this.j.a.hashCode() + d0.f(d0.b(this.h, (this.g.hashCode() + d0.d(d0.e((this.d.hashCode() + d0.d((this.b.hashCode() + (Long.hashCode(this.a) * 31)) * 31, 31, this.c)) * 31, 31, this.e), 31, this.f)) * 31, 31), 31, this.i.a);
    }

    public final String toString() {
        return "AlternativeQuestion(studiableItemId=" + this.a + ", studiableItemType=" + this.b + ", studiableContainerId=" + this.c + ", studiableContainerType=" + this.d + ", modelVersion=" + this.e + ", predictionTimestamp=" + this.f + ", studiableMetadataCategory=" + this.g + ", studiableMetadataRank=" + this.h + ", prompt=" + this.i + ", answer=" + this.j + ")";
    }
}
