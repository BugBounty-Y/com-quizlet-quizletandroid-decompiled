package com.quizlet.remote.model.notes;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.exceptions.notes.UpdatePrivacySettingsException;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.base.ModelError;
import com.quizlet.remote.service.q;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class c extends i implements Function2 {
    public int j;
    public final /* synthetic */ boolean k;
    public final /* synthetic */ e l;
    public final /* synthetic */ String m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(e eVar, String str, h hVar, boolean z) {
        super(2, hVar);
        this.k = z;
        this.l = eVar;
        this.m = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new c(this.l, this.m, hVar, this.k);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws UpdatePrivacySettingsException {
        ModelError modelError;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        e eVar = this.l;
        if (i == 0) {
            Z.e(obj);
            StudyNotesRequest studyNotesRequest = new StudyNotesRequest(this.k);
            q qVar = (q) eVar.b;
            this.j = 1;
            obj = qVar.a(this.m, studyNotesRequest, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) obj;
        RemoteNotesResponse remoteNotesResponse = (RemoteNotesResponse) apiThreeWrapper.a();
        if (remoteNotesResponse == null || remoteNotesResponse.c == null) {
            return Unit.a;
        }
        ((org.slf4j.b) eVar.d).m("Unable to update notes privacy settings from remote");
        RemoteNotesResponse remoteNotesResponse2 = (RemoteNotesResponse) apiThreeWrapper.a();
        throw new UpdatePrivacySettingsException((remoteNotesResponse2 == null || (modelError = remoteNotesResponse2.c) == null) ? null : modelError.a);
    }
}
