package assistantMode.refactored.types;

import androidx.compose.animation.d0;
import assistantMode.enums.m;
import assistantMode.refactored.enums.j;
import assistantMode.refactored.enums.l;
import assistantMode.refactored.modelTypes.CardSideDistractor$$serializer;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class MLMCQDistractorStudiableMetadata implements f {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] j = {null, null, null, null, null, null, null, new C5048d(CardSideDistractor$$serializer.INSTANCE, 0), new C5048d(q0.a, 0)};
    public final long a;
    public final l b;
    public final long c;
    public final j d;
    public final String e;
    public final long f;
    public final m g;
    public final List h;
    public final List i;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return MLMCQDistractorStudiableMetadata$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ MLMCQDistractorStudiableMetadata(int i, long j2, l lVar, long j3, j jVar, String str, long j4, m mVar, List list, List list2) {
        if (511 != (i & 511)) {
            AbstractC5047c0.k(i, 511, MLMCQDistractorStudiableMetadata$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = j2;
        this.b = lVar;
        this.c = j3;
        this.d = jVar;
        this.e = str;
        this.f = j4;
        this.g = mVar;
        this.h = list;
        this.i = list2;
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
        if (!(obj instanceof MLMCQDistractorStudiableMetadata)) {
            return false;
        }
        MLMCQDistractorStudiableMetadata mLMCQDistractorStudiableMetadata = (MLMCQDistractorStudiableMetadata) obj;
        return this.a == mLMCQDistractorStudiableMetadata.a && this.b == mLMCQDistractorStudiableMetadata.b && this.c == mLMCQDistractorStudiableMetadata.c && this.d == mLMCQDistractorStudiableMetadata.d && Intrinsics.b(this.e, mLMCQDistractorStudiableMetadata.e) && this.f == mLMCQDistractorStudiableMetadata.f && this.g == mLMCQDistractorStudiableMetadata.g && Intrinsics.b(this.h, mLMCQDistractorStudiableMetadata.h) && Intrinsics.b(this.i, mLMCQDistractorStudiableMetadata.i);
    }

    public final int hashCode() {
        return this.i.hashCode() + d0.f(assistantMode.refactored.a.e(this.g, d0.d(d0.e((this.d.hashCode() + d0.d((this.b.hashCode() + (Long.hashCode(this.a) * 31)) * 31, 31, this.c)) * 31, 31, this.e), 31, this.f), 31), 31, this.h);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MLMCQDistractorStudiableMetadata(studiableItemId=");
        sb.append(this.a);
        sb.append(", studiableItemType=");
        sb.append(this.b);
        sb.append(", studiableContainerId=");
        sb.append(this.c);
        sb.append(", studiableContainerType=");
        sb.append(this.d);
        sb.append(", modelVersion=");
        sb.append(this.e);
        sb.append(", predictionTimestamp=");
        sb.append(this.f);
        sb.append(", answerCardSideLabel=");
        sb.append(this.g);
        sb.append(", distractors=");
        sb.append(this.h);
        sb.append(", generators=");
        return android.support.v4.media.session.a.n(")", sb, this.i);
    }
}
