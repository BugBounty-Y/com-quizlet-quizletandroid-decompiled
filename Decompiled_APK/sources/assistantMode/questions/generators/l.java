package assistantMode.questions.generators;

import assistantMode.enums.m;
import assistantMode.refactored.types.SpellingQuestion;
import assistantMode.refactored.types.WrittenQuestion;
import assistantMode.types.B;
import assistantMode.types.C1454a;
import assistantMode.types.C1457d;
import assistantMode.types.QuestionElement;
import assistantMode.types.QuestionMetadata;
import assistantMode.types.unions.AudioAttribute;
import assistantMode.types.unions.TextAttribute;
import com.comscore.streaming.AdvertisementType;
import com.google.android.gms.internal.mlkit_vision_camera.M2;
import com.google.android.gms.internal.mlkit_vision_camera.N2;
import com.google.android.gms.internal.mlkit_vision_camera.P2;
import com.google.android.gms.internal.mlkit_vision_camera.Q2;
import com.google.android.gms.internal.mlkit_vision_camera.R2;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class l extends Q2 {
    public final /* synthetic */ int a;
    public final B b;
    public final assistantMode.utils.h c;
    public final C1454a d;
    public final long e;
    public final assistantMode.refactored.types.d f;

    public l(B questionConfig, assistantMode.utils.h studyableMaterialDataSource, int i) {
        AudioAttribute audioAttributeE;
        this.a = i;
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(questionConfig, "questionConfig");
                Intrinsics.checkNotNullParameter(studyableMaterialDataSource, "studyableMaterialDataSource");
                assistantMode.enums.k questionType = assistantMode.enums.k.b;
                Intrinsics.checkNotNullParameter(questionType, "questionType");
                this.b = questionConfig;
                this.c = studyableMaterialDataSource;
                C1454a c1454a = (C1454a) questionConfig.a().get(0);
                this.d = c1454a;
                C1457d c1457d = questionConfig.a;
                QuestionElement questionElementC = N2.c(c1454a, c1457d.b);
                QuestionElement questionElementC2 = N2.c(c1454a, c1457d.c);
                this.e = c1454a.a.a;
                for (Object obj : questionElementC2.a) {
                    if (obj instanceof TextAttribute) {
                        if (obj == null) {
                            throw new NullPointerException("null cannot be cast to non-null type assistantMode.types.unions.TextAttribute");
                        }
                        String str = ((TextAttribute) obj).b;
                        QuestionElement questionElementD = R2.d(this.b, this.d);
                        Long lValueOf = Long.valueOf(this.e);
                        C1457d c1457d2 = this.b.a;
                        this.f = new WrittenQuestion(questionElementC, str, questionElementD, new QuestionMetadata(lValueOf, c1457d2.b, c1457d2.c, null, this.c.h(this.e), this.c.j(), 136));
                        return;
                    }
                }
                throw new NoSuchElementException("Collection contains no element matching the predicate.");
            default:
                Intrinsics.checkNotNullParameter(questionConfig, "questionConfig");
                Intrinsics.checkNotNullParameter(studyableMaterialDataSource, "studyableMaterialDataSource");
                assistantMode.enums.k questionType2 = assistantMode.enums.k.i;
                Intrinsics.checkNotNullParameter(questionType2, "questionType");
                this.b = questionConfig;
                this.c = studyableMaterialDataSource;
                C1454a card = (C1454a) questionConfig.a().get(0);
                this.d = card;
                C1457d c1457d3 = questionConfig.a;
                QuestionElement questionElementC3 = N2.c(card, c1457d3.b);
                ArrayList arrayList = new ArrayList();
                for (Object obj2 : questionElementC3.a) {
                    if (((assistantMode.types.unions.a) obj2).a() != assistantMode.refactored.enums.h.e) {
                        arrayList.add(obj2);
                    }
                }
                ArrayList attributes = CollectionsKt.y0(arrayList);
                Intrinsics.checkNotNullParameter(card, "card");
                m cardSide = c1457d3.c;
                Intrinsics.checkNotNullParameter(cardSide, "cardSide");
                int iOrdinal = cardSide.ordinal();
                if (iOrdinal == 0) {
                    audioAttributeE = M2.e(card);
                } else {
                    if (iOrdinal != 1) {
                        throw new IllegalArgumentException("Cannot create audio for card side: " + cardSide);
                    }
                    audioAttributeE = M2.b(card);
                }
                if (audioAttributeE != null) {
                    attributes.add(audioAttributeE);
                }
                Intrinsics.checkNotNullParameter(attributes, "attributes");
                QuestionElement questionElement = new QuestionElement(attributes);
                QuestionElement questionElementC4 = N2.c(this.d, this.b.a.c);
                this.e = this.d.a.a;
                for (Object obj3 : questionElementC4.a) {
                    if (obj3 instanceof TextAttribute) {
                        if (obj3 == null) {
                            throw new NullPointerException("null cannot be cast to non-null type assistantMode.types.unions.TextAttribute");
                        }
                        String str2 = ((TextAttribute) obj3).b;
                        Long lValueOf2 = Long.valueOf(this.e);
                        C1457d c1457d4 = this.b.a;
                        this.f = new SpellingQuestion(questionElement, str2, new QuestionMetadata(lValueOf2, c1457d4.b, c1457d4.c, null, null, null, AdvertisementType.BRANDED_ON_DEMAND_MID_ROLL));
                        return;
                    }
                }
                throw new NoSuchElementException("Collection contains no element matching the predicate.");
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public final assistantMode.grading.d c() {
        switch (this.a) {
            case 0:
                return P2.b(this, this.b, this.c);
            default:
                return P2.b(this, this.b, this.c);
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public final assistantMode.refactored.types.d d() {
        switch (this.a) {
            case 0:
                return (SpellingQuestion) this.f;
            default:
                return (WrittenQuestion) this.f;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Q2
    public final List e() {
        switch (this.a) {
            case 0:
                List listA = this.b.a();
                ArrayList arrayList = new ArrayList(C.q(listA, 10));
                Iterator it2 = listA.iterator();
                while (it2.hasNext()) {
                    arrayList.add(Long.valueOf(((C1454a) it2.next()).a.a));
                }
                return arrayList;
            default:
                List listA2 = this.b.a();
                ArrayList arrayList2 = new ArrayList(C.q(listA2, 10));
                Iterator it3 = listA2.iterator();
                while (it3.hasNext()) {
                    arrayList2.add(Long.valueOf(((C1454a) it3.next()).a.a));
                }
                return arrayList2;
        }
    }
}
