package assistantMode.types;

import com.quizlet.shared.models.api.metering.MeteredEvent$$serializer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class QuestionMetadata implements F {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] i;
    public final Long a;
    public final assistantMode.enums.m b;
    public final assistantMode.enums.m c;
    public final List d;
    public final QuestionScoringInferenceMetadata e;
    public final QuestionStudiableMetadata f;
    public final Map g;
    public Map h;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return QuestionMetadata$$serializer.INSTANCE;
        }
    }

    static {
        q0 q0Var = q0.a;
        i = new KSerializer[]{null, null, null, new C5048d(q0Var, 0), null, null, new kotlinx.serialization.internal.F(assistantMode.enums.r.f, q0Var, 1), new kotlinx.serialization.internal.F(com.quizlet.shared.enums.g.f, MeteredEvent$$serializer.INSTANCE, 1)};
    }

    public QuestionMetadata(int i2, Long l, assistantMode.enums.m mVar, assistantMode.enums.m mVar2, List list, QuestionScoringInferenceMetadata questionScoringInferenceMetadata, QuestionStudiableMetadata questionStudiableMetadata, Map map, Map map2) {
        QuestionStudiableMetadata questionStudiableMetadata2;
        if (7 != (i2 & 7)) {
            AbstractC5047c0.k(i2, 7, QuestionMetadata$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = l;
        this.b = mVar;
        this.c = mVar2;
        if ((i2 & 8) == 0) {
            this.d = null;
        } else {
            this.d = list;
        }
        if ((i2 & 16) == 0) {
            this.e = null;
        } else {
            this.e = questionScoringInferenceMetadata;
        }
        if ((i2 & 32) == 0) {
            K k = K.a;
            questionStudiableMetadata2 = new QuestionStudiableMetadata(k, k, k, k, k);
        } else {
            questionStudiableMetadata2 = questionStudiableMetadata;
        }
        this.f = questionStudiableMetadata2;
        if ((i2 & 64) == 0) {
            this.g = null;
        } else {
            this.g = map;
        }
        if ((i2 & 128) == 0) {
            this.h = null;
        } else {
            this.h = map2;
        }
    }

    @Override // assistantMode.types.F
    public final void a(LinkedHashMap linkedHashMap) {
        this.h = linkedHashMap;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof QuestionMetadata)) {
            return false;
        }
        QuestionMetadata questionMetadata = (QuestionMetadata) obj;
        return Intrinsics.b(this.a, questionMetadata.a) && this.b == questionMetadata.b && this.c == questionMetadata.c && Intrinsics.b(this.d, questionMetadata.d) && Intrinsics.b(this.e, questionMetadata.e) && Intrinsics.b(this.f, questionMetadata.f) && Intrinsics.b(this.g, questionMetadata.g) && Intrinsics.b(this.h, questionMetadata.h);
    }

    public final int hashCode() {
        Long l = this.a;
        int iHashCode = (l == null ? 0 : l.hashCode()) * 31;
        assistantMode.enums.m mVar = this.b;
        int iHashCode2 = (iHashCode + (mVar == null ? 0 : mVar.hashCode())) * 31;
        assistantMode.enums.m mVar2 = this.c;
        int iHashCode3 = (iHashCode2 + (mVar2 == null ? 0 : mVar2.hashCode())) * 31;
        List list = this.d;
        int iHashCode4 = (iHashCode3 + (list == null ? 0 : list.hashCode())) * 31;
        QuestionScoringInferenceMetadata questionScoringInferenceMetadata = this.e;
        int iHashCode5 = (iHashCode4 + (questionScoringInferenceMetadata == null ? 0 : questionScoringInferenceMetadata.hashCode())) * 31;
        QuestionStudiableMetadata questionStudiableMetadata = this.f;
        int iHashCode6 = (iHashCode5 + (questionStudiableMetadata == null ? 0 : questionStudiableMetadata.hashCode())) * 31;
        Map map = this.g;
        int iHashCode7 = (iHashCode6 + (map == null ? 0 : map.hashCode())) * 31;
        Map map2 = this.h;
        return iHashCode7 + (map2 != null ? map2.hashCode() : 0);
    }

    public final String toString() {
        return "QuestionMetadata(studiableItemId=" + this.a + ", promptSide=" + this.b + ", answerSide=" + this.c + ", optionGenerationSource=" + this.d + ", questionScoringInferenceMetadata=" + this.e + ", questionStudiableMetadata=" + this.f + ", studiableMetadataVersions=" + this.g + ", meteringData=" + this.h + ")";
    }

    public QuestionMetadata(Long l, assistantMode.enums.m mVar, assistantMode.enums.m mVar2, ArrayList arrayList, QuestionStudiableMetadata questionStudiableMetadata, LinkedHashMap linkedHashMap, int i2) {
        arrayList = (i2 & 8) != 0 ? null : arrayList;
        if ((i2 & 32) != 0) {
            K k = K.a;
            questionStudiableMetadata = new QuestionStudiableMetadata(k, k, k, k, k);
        }
        linkedHashMap = (i2 & 64) != 0 ? null : linkedHashMap;
        this.a = l;
        this.b = mVar;
        this.c = mVar2;
        this.d = arrayList;
        this.e = null;
        this.f = questionStudiableMetadata;
        this.g = linkedHashMap;
        this.h = null;
    }
}
