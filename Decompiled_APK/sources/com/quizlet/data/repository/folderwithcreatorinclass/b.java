package com.quizlet.data.repository.folderwithcreatorinclass;

import com.braze.C1510p;
import com.braze.requests.framework.o;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.datatransport.cct.internal.s;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3738u6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3770y6;
import com.quizlet.assembly.compose.listitems.r;
import com.quizlet.data.connectivity.NetworkOfflineError;
import com.quizlet.data.repository.studysetwithcreatorinclass.g;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBTermFields;
import com.quizlet.infra.legacysyncengine.models.identity.QueryIdFieldChangeMapper;
import com.quizlet.quizletandroid.k;
import com.quizlet.remote.service.E;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.j;
import io.reactivex.rxjava3.internal.operators.maybe.h;
import io.reactivex.rxjava3.internal.operators.maybe.w;
import io.reactivex.rxjava3.internal.operators.observable.L;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class b implements j {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ Object c;

    public /* synthetic */ b(long j, s sVar) {
        this.a = 5;
        this.b = j;
        this.c = sVar;
    }

    @Override // io.reactivex.rxjava3.functions.j
    public final Object get() {
        switch (this.a) {
            case 0:
                e eVar = (e) this.c;
                return AbstractC3738u6.b((com.quizlet.data.connectivity.a) eVar.d, new C1510p(eVar, this.b, 13), new r(17)).m();
            case 1:
                com.quizlet.data.repository.studysetwithcreator.d dVar = (com.quizlet.data.repository.studysetwithcreator.d) this.c;
                i iVarM = AbstractC3738u6.b((com.quizlet.data.connectivity.a) dVar.b, new C1510p(dVar, this.b, 14), new r(17)).m().m(com.quizlet.data.repository.studysetwithcreator.c.c, SubsamplingScaleImageView.TILE_SIZE_AUTO);
                Intrinsics.checkNotNullExpressionValue(iVarM, "flatMap(...)");
                return iVarM;
            case 2:
                g gVar = (g) this.c;
                return AbstractC3738u6.b((com.quizlet.data.connectivity.a) gVar.e, new C1510p(gVar, this.b, 15), new r(17)).m();
            case 3:
                com.quizlet.data.repository.user.a aVar = (com.quizlet.data.repository.user.a) this.c;
                com.quizlet.remote.model.user.a aVar2 = (com.quizlet.remote.model.user.a) ((com.quizlet.data.repository.activitycenter.b) aVar.b).c;
                io.reactivex.rxjava3.internal.operators.single.g gVarG = ((E) aVar2.a).a(this.b).g(new k(aVar2, 16));
                Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
                w connected = new h(1, AbstractC3770y6.b(gVarG), new com.google.android.material.floatingactionbutton.c(aVar, 16)).h();
                Intrinsics.checkNotNullExpressionValue(connected, "toSingle(...)");
                io.reactivex.rxjava3.internal.operators.flowable.b notConnected = p.d(new NetworkOfflineError(0));
                com.quizlet.data.connectivity.a aVar3 = (com.quizlet.data.connectivity.a) aVar.c;
                Intrinsics.checkNotNullParameter(aVar3, "<this>");
                Intrinsics.checkNotNullParameter(connected, "connected");
                Intrinsics.checkNotNullParameter(notConnected, "notConnected");
                return AbstractC3738u6.b(aVar3, new o(connected, 22), new o(notConnected, 23)).m();
            case 4:
                com.quizlet.data.repository.user.e eVar2 = (com.quizlet.data.repository.user.e) this.c;
                return AbstractC3738u6.b((com.quizlet.data.connectivity.a) eVar2.c, new C1510p(eVar2, this.b, 16), new r(17)).m();
            default:
                com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.TERM);
                bVar.b(Long.valueOf(this.b), DBTermFields.SET);
                com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar.a();
                s sVar = (s) this.c;
                return new L(((s) sVar.e).h(((QueryIdFieldChangeMapper) sVar.d).convertStaleLocalIds(aVarA)).e(), new k(sVar, 1));
        }
    }

    public /* synthetic */ b(Object obj, long j, int i) {
        this.a = i;
        this.c = obj;
        this.b = j;
    }
}
