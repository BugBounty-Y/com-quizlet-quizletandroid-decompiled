package com.google.android.gms.internal.mlkit_vision_camera;

import assistantMode.refactored.modelTypes.DiagramShapeValue;
import assistantMode.refactored.modelTypes.ImageValue;
import assistantMode.types.C1454a;
import assistantMode.types.QuestionElement;
import assistantMode.types.unions.AudioAttribute;
import assistantMode.types.unions.ImageAttribute;
import assistantMode.types.unions.LocationAttribute;
import assistantMode.types.unions.TextAttribute;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;
import org.wordpress.aztec.EnumC5145a;
import org.wordpress.aztec.spans.C5164l;
import org.wordpress.aztec.spans.C5165m;

/* loaded from: classes2.dex */
public abstract class N2 {
    public static final C5164l a(int i, EnumC5145a alignmentRendering, C5146b attributes, org.wordpress.aztec.formatting.d listItemStyle) {
        Intrinsics.checkNotNullParameter(alignmentRendering, "alignmentRendering");
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(listItemStyle, "listItemStyle");
        int iOrdinal = alignmentRendering.ordinal();
        if (iOrdinal != 0) {
            if (iOrdinal == 1) {
                return new C5164l(i, attributes, listItemStyle);
            }
            throw new NoWhenBranchMatchedException();
        }
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(listItemStyle, "listItemStyle");
        C5165m c5165m = new C5165m(i, attributes, listItemStyle);
        c5165m.g = null;
        return c5165m;
    }

    public static /* synthetic */ C5164l b(int i, EnumC5145a enumC5145a, C5146b c5146b, org.wordpress.aztec.formatting.d dVar, int i2) {
        if ((i2 & 4) != 0) {
            c5146b = new C5146b();
        }
        if ((i2 & 8) != 0) {
            dVar = new org.wordpress.aztec.formatting.d(false, 0);
        }
        return a(i, enumC5145a, c5146b, dVar);
    }

    public static final QuestionElement c(C1454a card, assistantMode.enums.m side) {
        ArrayList arrayListK;
        Intrinsics.checkNotNullParameter(card, "card");
        Intrinsics.checkNotNullParameter(side, "side");
        Intrinsics.checkNotNullParameter(card, "card");
        Intrinsics.checkNotNullParameter(side, "side");
        int iOrdinal = side.ordinal();
        AudioAttribute audioAttributeE = null;
        if (iOrdinal == 0) {
            Intrinsics.checkNotNullParameter(card, "card");
            k3 text = card.i(assistantMode.enums.m.b);
            Intrinsics.checkNotNullParameter(text, "text");
            arrayListK = kotlin.collections.B.k(new TextAttribute(text.e(), text.c(), text.f()));
        } else if (iOrdinal == 1) {
            Intrinsics.checkNotNullParameter(card, "card");
            k3 text2 = card.i(assistantMode.enums.m.c);
            Intrinsics.checkNotNullParameter(text2, "text");
            arrayListK = kotlin.collections.B.k(new TextAttribute(text2.e(), text2.c(), text2.f()));
        } else {
            if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            Intrinsics.checkNotNullParameter(card, "card");
            DiagramShapeValue diagramShapeValue = (DiagramShapeValue) card.l.getValue();
            if (diagramShapeValue == null) {
                throw new IllegalStateException("Cannot create location attribute without diagramShape");
            }
            ImageValue imageValue = card.e;
            arrayListK = kotlin.collections.B.k(new LocationAttribute(diagramShapeValue.a, imageValue != null ? assistantMode.utils.g.n(imageValue) : null));
        }
        int iOrdinal2 = side.ordinal();
        if (iOrdinal2 == 0) {
            audioAttributeE = M2.e(card);
        } else if (iOrdinal2 == 1) {
            audioAttributeE = M2.b(card);
        } else if (iOrdinal2 != 2) {
            throw new NoWhenBranchMatchedException();
        }
        if (audioAttributeE != null) {
            arrayListK.add(audioAttributeE);
        }
        assistantMode.enums.m mVar = assistantMode.enums.m.c;
        ImageAttribute imageAttributeH = card.h(mVar);
        if (side == mVar && imageAttributeH != null) {
            arrayListK.add(imageAttributeH);
        }
        return new QuestionElement(arrayListK);
    }

    public static final ArrayList d(assistantMode.enums.m side, List cards) {
        Intrinsics.checkNotNullParameter(cards, "cards");
        Intrinsics.checkNotNullParameter(side, "side");
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(cards, 10));
        Iterator it2 = cards.iterator();
        while (it2.hasNext()) {
            arrayList.add(c((C1454a) it2.next(), side));
        }
        return arrayList;
    }

    public static final QuestionElement e(List list) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        return new QuestionElement(assistantMode.utils.g.o(list));
    }
}
