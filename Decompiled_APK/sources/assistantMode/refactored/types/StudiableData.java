package assistantMode.refactored.types;

import assistantMode.enums.r;
import assistantMode.refactored.modelTypes.Card;
import assistantMode.refactored.modelTypes.Card$$serializer;
import assistantMode.refactored.modelTypes.CustomMultipleChoiceQuestion;
import assistantMode.refactored.modelTypes.CustomMultipleChoiceQuestion$$serializer;
import assistantMode.refactored.modelTypes.ImageValue$$serializer;
import java.lang.annotation.Annotation;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import kotlinx.serialization.internal.F;
import kotlinx.serialization.internal.P;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class StudiableData {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] d = {new C5048d(new kotlinx.serialization.e("assistantMode.refactored.modelTypes.StudiableItem", K.a(assistantMode.refactored.modelTypes.d.class), new kotlin.reflect.c[]{K.a(Card.class), K.a(CustomMultipleChoiceQuestion.class)}, new KSerializer[]{Card$$serializer.INSTANCE, CustomMultipleChoiceQuestion$$serializer.INSTANCE}, new Annotation[0]), 0), new F(P.a, ImageValue$$serializer.INSTANCE, 1), new F(r.f, StudiableMetadataContent$$serializer.INSTANCE, 1)};
    public final List a;
    public final Map b;
    public final Map c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return StudiableData$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ StudiableData(int i, List list, Map map, Map map2) {
        if (1 != (i & 1)) {
            AbstractC5047c0.k(i, 1, StudiableData$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = list;
        if ((i & 2) == 0) {
            this.b = V.c();
        } else {
            this.b = map;
        }
        if ((i & 4) == 0) {
            this.c = V.c();
        } else {
            this.c = map2;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudiableData)) {
            return false;
        }
        StudiableData studiableData = (StudiableData) obj;
        return Intrinsics.b(this.a, studiableData.a) && Intrinsics.b(this.b, studiableData.b) && Intrinsics.b(this.c, studiableData.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + assistantMode.refactored.a.d(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        return "StudiableData(studiableItems=" + this.a + ", setIdToDiagramImage=" + this.b + ", studiableMetadataByType=" + this.c + ")";
    }

    public StudiableData(List studiableItems, Map setIdToDiagramImage, Map studiableMetadataByType) {
        Intrinsics.checkNotNullParameter(studiableItems, "studiableItems");
        Intrinsics.checkNotNullParameter(setIdToDiagramImage, "setIdToDiagramImage");
        Intrinsics.checkNotNullParameter(studiableMetadataByType, "studiableMetadataByType");
        this.a = studiableItems;
        this.b = setIdToDiagramImage;
        this.c = studiableMetadataByType;
    }
}
