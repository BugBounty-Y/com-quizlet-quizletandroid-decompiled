package com.quizlet.remote.model.universaluploadflow;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.exceptions.universaluploadflow.UniversalUploadFlowException;
import com.quizlet.db.data.models.base.AssociationNames;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.service.D;
import java.util.Map;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.V;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public int j;
    public final /* synthetic */ com.quizlet.remote.model.notes.e k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(com.quizlet.remote.model.notes.e eVar, String str, h hVar) {
        super(2, hVar);
        this.k = eVar;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new d(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws UniversalUploadFlowException {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        com.quizlet.remote.model.notes.e eVar = this.k;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.remote.model.notes.e.e(eVar);
            D d = (D) eVar.b;
            Boolean bool = Boolean.TRUE;
            Map<String, Boolean> mapF = V.f(new Pair("filters[sessions][isVisible]", bool), new Pair("filters[sessions][repeatSets]", Boolean.FALSE), new Pair("filters[sets][isPublished]", bool), new Pair("filters[sets][practiceTestEligibility]", bool));
            Map<String, String> mapF2 = V.f(new Pair("include[classSet][0]", "set"), new Pair("include[classSet][set]", AssociationNames.CREATOR), new Pair("include[session][0]", "set"), new Pair("include[session][set]", AssociationNames.CREATOR), new Pair("include[set]", AssociationNames.CREATOR));
            this.j = 1;
            obj = d.e(mapF, mapF2, this.l, null, null, null, null, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        RemoteUniversalUploadFlowFlashcardSetsResponse remoteUniversalUploadFlowFlashcardSetsResponse = (RemoteUniversalUploadFlowFlashcardSetsResponse) ((ApiThreeWrapper) obj).a();
        UniversalUploadFlowFlashcardSetsResponse universalUploadFlowFlashcardSetsResponse = remoteUniversalUploadFlowFlashcardSetsResponse != null ? remoteUniversalUploadFlowFlashcardSetsResponse.d : null;
        if (universalUploadFlowFlashcardSetsResponse != null) {
            return ((com.quizlet.quizletandroid.logging.initializer.a) eVar.e).a(universalUploadFlowFlashcardSetsResponse);
        }
        throw new UniversalUploadFlowException("Flashcard sets data should not be null");
    }
}
