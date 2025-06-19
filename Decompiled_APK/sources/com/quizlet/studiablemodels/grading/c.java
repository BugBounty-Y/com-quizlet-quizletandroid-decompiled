package com.quizlet.studiablemodels.grading;

import assistantMode.enums.m;
import assistantMode.types.QuestionElement;
import assistantMode.types.QuestionMetadata;
import assistantMode.types.h;
import assistantMode.types.k;
import assistantMode.types.unions.AudioAttribute;
import assistantMode.types.unions.ImageAttribute;
import assistantMode.types.unions.LocationAttribute;
import assistantMode.types.unions.TextAttribute;
import assistantMode.types.unions.VideoAttribute;
import com.quizlet.studiablemodels.DefaultQuestionSectionData;
import com.quizlet.studiablemodels.LocationQuestionSectionData;
import com.quizlet.studiablemodels.QuestionSectionData;
import com.quizlet.studiablemodels.StudiableAudio;
import com.quizlet.studiablemodels.StudiableDiagramImage;
import com.quizlet.studiablemodels.StudiableDiagramShape;
import com.quizlet.studiablemodels.StudiableImage;
import com.quizlet.studiablemodels.StudiableQuestionMetadata;
import com.quizlet.studiablemodels.StudiableText;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class c {
    public static final boolean a(m mVar) {
        Intrinsics.checkNotNullParameter(mVar, "<this>");
        return mVar == m.d;
    }

    public static final StudiableDiagramImage b(k kVar) {
        Intrinsics.checkNotNullParameter(kVar, "<this>");
        Intrinsics.checkNotNullParameter(kVar, "<this>");
        int i = (int) kVar.m;
        int i2 = (int) kVar.h;
        String str = kVar.a;
        return new StudiableDiagramImage(kVar.i, new StudiableImage(kVar.b, i, str, str, i2));
    }

    public static final QuestionSectionData c(QuestionElement questionElement, List shapes) {
        Intrinsics.checkNotNullParameter(questionElement, "<this>");
        Intrinsics.checkNotNullParameter(shapes, "shapes");
        List list = questionElement.a;
        boolean z = false;
        if (list == null || !list.isEmpty()) {
            Iterator it2 = list.iterator();
            while (true) {
                if (!it2.hasNext()) {
                    break;
                }
                if (((assistantMode.types.unions.a) it2.next()) instanceof LocationAttribute) {
                    z = true;
                    break;
                }
            }
        }
        return d(questionElement, z, shapes);
    }

    public static final QuestionSectionData d(QuestionElement questionElement, boolean z, List list) {
        if (z) {
            if (questionElement.a.size() != 1) {
                throw new IllegalArgumentException("Multiple locations not supported in QuestionElement");
            }
            assistantMode.types.unions.a aVar = (assistantMode.types.unions.a) CollectionsKt.L(questionElement.a);
            if (!(aVar instanceof LocationAttribute)) {
                throw new IllegalArgumentException(("Invalid attribute type for LOCATION side: type [" + aVar.getClass() + "]").toString());
            }
            Iterator it2 = list.iterator();
            while (it2.hasNext()) {
                h hVar = (h) it2.next();
                LocationAttribute locationAttribute = (LocationAttribute) aVar;
                if (Intrinsics.b(hVar.b, locationAttribute.a)) {
                    return new LocationQuestionSectionData(hVar.c, new StudiableDiagramShape(locationAttribute.a));
                }
            }
            throw new NoSuchElementException("Collection contains no element matching the predicate.");
        }
        if (questionElement.a.size() > 3) {
            throw new IllegalArgumentException("Too many attributes not supported for QuestionElement");
        }
        StudiableText studiableText = null;
        StudiableImage studiableImage = null;
        StudiableAudio studiableAudio = null;
        for (assistantMode.types.unions.a aVar2 : questionElement.a) {
            if (aVar2 instanceof TextAttribute) {
                TextAttribute textAttribute = (TextAttribute) aVar2;
                studiableText = new StudiableText(textAttribute.a, textAttribute.b, textAttribute.c);
            } else if (aVar2 instanceof ImageAttribute) {
                ImageAttribute imageAttribute = (ImageAttribute) aVar2;
                String str = imageAttribute.a;
                studiableImage = new StudiableImage(str, imageAttribute.b, str, null, imageAttribute.c);
            } else if (aVar2 instanceof AudioAttribute) {
                studiableAudio = new StudiableAudio(((AudioAttribute) aVar2).a);
            } else if (!(aVar2 instanceof LocationAttribute) && !(aVar2 instanceof VideoAttribute)) {
                throw new NoWhenBranchMatchedException();
            }
        }
        return new DefaultQuestionSectionData(studiableText, studiableImage, studiableAudio);
    }

    public static final StudiableQuestionMetadata e(QuestionMetadata questionMetadata, assistantMode.enums.k kVar, List list) {
        m mVar = questionMetadata.b;
        if (mVar == null) {
            throw new IllegalArgumentException("Metadata from NSidedCards must have non-null prompt sides. Other StudiableItem types are unsupported.");
        }
        m mVar2 = questionMetadata.c;
        if (mVar2 == null) {
            throw new IllegalArgumentException("Metadata from NSidedCards must have non-null answer sides. Other StudiableItem types are unsupported.");
        }
        Long l = questionMetadata.a;
        long jLongValue = l != null ? l.longValue() : -1L;
        k kVar2 = (k) CollectionsKt.firstOrNull(list);
        StudiableDiagramImage studiableDiagramImageB = kVar2 != null ? b(kVar2) : null;
        if ((32 & 16) != 0) {
            studiableDiagramImageB = null;
        }
        return new StudiableQuestionMetadata(kVar, jLongValue, mVar, mVar2, studiableDiagramImageB, null);
    }
}
