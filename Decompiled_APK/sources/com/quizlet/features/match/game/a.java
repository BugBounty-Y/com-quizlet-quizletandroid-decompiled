package com.quizlet.features.match.game;

import com.quizlet.data.repository.folderset.c;
import com.quizlet.data.repository.metering.j;
import com.quizlet.features.infra.basestudy.manager.f;
import com.quizlet.features.match.data.S;
import com.quizlet.features.match.data.U;
import com.quizlet.features.match.settings.MatchSettingsData;
import io.reactivex.rxjava3.functions.h;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements h {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ j c;

    public a(j jVar, boolean z) {
        this.c = jVar;
        this.b = z;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        switch (this.a) {
            case 0:
                com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar = (com.quizlet.features.infra.basestudy.data.models.dataproviders.a) obj;
                j jVar = this.c;
                MatchSettingsData matchSettingsDataQ = ((c) jVar.b).q();
                int size = aVar.u.size();
                ArrayList arrayList = aVar.z;
                Intrinsics.checkNotNullExpressionValue(arrayList, "getAvailableStudiableCardSideLabels(...)");
                return new S(matchSettingsDataQ, size, arrayList, this.b, ((f) jVar.a).d());
            default:
                com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar2 = (com.quizlet.features.infra.basestudy.data.models.dataproviders.a) obj;
                j jVar2 = this.c;
                f fVar = (f) jVar2.a;
                boolean z = fVar.k;
                boolean z2 = this.b;
                if (z2 != z) {
                    fVar.n(z2);
                }
                ArrayList termList = aVar2.s;
                Intrinsics.checkNotNullExpressionValue(termList, "getTerms(...)");
                List diagramShapes = aVar2.a();
                Intrinsics.checkNotNullExpressionValue(diagramShapes, "getDiagramShapes(...)");
                List imageRefs = aVar2.b();
                Intrinsics.checkNotNullExpressionValue(imageRefs, "getImageRefs(...)");
                MatchSettingsData settings = ((c) jVar2.b).q();
                Intrinsics.checkNotNullParameter(termList, "termList");
                Intrinsics.checkNotNullParameter(diagramShapes, "diagramShapes");
                Intrinsics.checkNotNullParameter(imageRefs, "imageRefs");
                Intrinsics.checkNotNullParameter(settings, "settings");
                return new U(termList, diagramShapes, imageRefs, settings);
        }
    }

    public a(boolean z, j jVar) {
        this.b = z;
        this.c = jVar;
    }
}
