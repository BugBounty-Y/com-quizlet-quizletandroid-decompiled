package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.layout.AbstractC0897s;
import com.quizlet.data.model.C4124e1;
import com.quizlet.db.data.models.persisted.DBDiagramShape;
import com.quizlet.db.data.models.persisted.DBImage;
import com.quizlet.studiablemodels.LocationQuestionSectionData;
import com.quizlet.studiablemodels.StudiableDiagramImage;
import com.quizlet.studiablemodels.StudiableImage;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.d5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3124d5 {
    public static final void a(C4124e1 progressData, Function0 onCardMenuClick, Function1 onProgressItemCtaButtonClick, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(progressData, "progressData");
        Intrinsics.checkNotNullParameter(onCardMenuClick, "onCardMenuClick");
        Intrinsics.checkNotNullParameter(onProgressItemCtaButtonClick, "onProgressItemCtaButtonClick");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(557095358);
        if (((i | (c0814p2.h(progressData) ? 4 : 2) | (c0814p2.h(onCardMenuClick) ? 32 : 16) | (c0814p2.h(onProgressItemCtaButtonClick) ? 256 : 128) | 3072) & 1171) == 1170 && c0814p2.x()) {
            c0814p2.Q();
            nVar2 = nVar;
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            c0814p = c0814p2;
            com.google.android.gms.internal.mlkit_vision_document_scanner.R4.a(androidx.compose.foundation.layout.K0.q(nVar3, DefinitionKt.NO_Float_VALUE, com.quizlet.themes.m.f1, 1), null, 0L, 0L, 0L, null, false, null, null, null, androidx.compose.runtime.internal.e.e(2069730372, new com.quizlet.assembly.compose.menu.l(progressData, onProgressItemCtaButtonClick, onCardMenuClick, 11), c0814p2), c0814p, 0, 1022);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i(progressData, onCardMenuClick, onProgressItemCtaButtonClick, nVar2, i);
        }
    }

    public static final DBDiagramShape b(LocationQuestionSectionData locationQuestionSectionData) {
        Intrinsics.checkNotNullParameter(locationQuestionSectionData, "<this>");
        DBDiagramShape dBDiagramShape = new DBDiagramShape();
        dBDiagramShape.setTermId(locationQuestionSectionData.a);
        dBDiagramShape.setShape(locationQuestionSectionData.b.a);
        return dBDiagramShape;
    }

    public static final DBImage c(StudiableDiagramImage studiableDiagramImage) {
        Intrinsics.checkNotNullParameter(studiableDiagramImage, "<this>");
        DBImage dBImage = new DBImage();
        dBImage.setId(studiableDiagramImage.a);
        StudiableImage studiableImage = studiableDiagramImage.b;
        dBImage.setServerSmallUrl(studiableImage.a);
        dBImage.setServerMediumUrl(studiableImage.b);
        dBImage.setServerLargeUrl(studiableImage.c);
        dBImage.setWidth(Integer.valueOf(studiableImage.d));
        dBImage.setHeight(Integer.valueOf(studiableImage.e));
        return dBImage;
    }

    /* JADX WARN: Type inference failed for: r3v5, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    public static final void d(androidx.compose.ui.semantics.o oVar, int i, androidx.compose.ui.scrollcapture.k kVar) {
        androidx.compose.ui.semantics.o oVar2;
        androidx.compose.runtime.collection.b bVar = new androidx.compose.runtime.collection.b(new androidx.compose.ui.semantics.o[16]);
        List listG = oVar.g(false, false);
        while (true) {
            bVar.e(bVar.c, listG);
            while (bVar.m()) {
                oVar2 = (androidx.compose.ui.semantics.o) bVar.o(bVar.c - 1);
                if (androidx.compose.ui.platform.N.B(oVar2)) {
                    androidx.compose.ui.semantics.u uVar = androidx.compose.ui.semantics.r.i;
                    androidx.compose.ui.semantics.k kVar2 = oVar2.d;
                    LinkedHashMap linkedHashMap = kVar2.a;
                    if (linkedHashMap.containsKey(uVar)) {
                        continue;
                    } else {
                        androidx.compose.ui.node.a0 a0VarC = oVar2.c();
                        if (a0VarC == null) {
                            W4.g("Expected semantics node to have a coordinator.");
                            throw null;
                        }
                        androidx.compose.ui.unit.i iVarB = Q5.b(AbstractC0897s.f(a0VarC));
                        if (iVarB.a < iVarB.c && iVarB.b < iVarB.d) {
                            Object obj = kVar2.a.get(androidx.compose.ui.semantics.j.e);
                            if (obj == null) {
                                obj = null;
                            }
                            Function2 function2 = (Function2) obj;
                            Object obj2 = linkedHashMap.get(androidx.compose.ui.semantics.r.p);
                            androidx.compose.ui.semantics.i iVar = (androidx.compose.ui.semantics.i) (obj2 != null ? obj2 : null);
                            if (function2 == null || iVar == null || ((Number) iVar.b.invoke()).floatValue() <= DefinitionKt.NO_Float_VALUE) {
                                break;
                            }
                            int i2 = i + 1;
                            kVar.invoke(new androidx.compose.ui.scrollcapture.m(oVar2, i2, iVarB, a0VarC));
                            d(oVar2, i2, kVar);
                        }
                    }
                }
            }
            return;
            listG = oVar2.g(false, false);
        }
    }
}
