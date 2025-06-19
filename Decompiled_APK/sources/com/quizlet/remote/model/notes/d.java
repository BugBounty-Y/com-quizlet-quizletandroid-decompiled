package com.quizlet.remote.model.notes;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.exceptions.notes.UpdateTitleException;
import com.quizlet.data.model.R1;
import com.quizlet.quizletandroid.k;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.base.ModelError;
import com.quizlet.remote.service.q;
import java.util.List;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public int j;
    public final /* synthetic */ String k;
    public final /* synthetic */ e l;
    public final /* synthetic */ String m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(String str, e eVar, String str2, h hVar) {
        super(2, hVar);
        this.k = str;
        this.l = eVar;
        this.m = str2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new d(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws UpdateTitleException {
        StudyNoteArtifact studyNoteArtifact;
        List list;
        MagicNotesArtifactResponse magicNotesArtifactResponse;
        R1 r1;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        e eVar = this.l;
        if (i == 0) {
            Z.e(obj);
            StudyNotesArtifactRequest studyNotesArtifactRequest = new StudyNotesArtifactRequest(false, android.support.v4.media.session.a.t(new StringBuilder("{\"title\":\""), this.k, "\"}"), 1, null);
            q qVar = (q) eVar.b;
            this.j = 1;
            obj = qVar.c(this.m, studyNotesArtifactRequest, this);
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
        try {
            RemoteStudyNotesArtifactsResponse remoteStudyNotesArtifactsResponse = (RemoteStudyNotesArtifactsResponse) apiThreeWrapper.a();
            if (remoteStudyNotesArtifactsResponse != null && (studyNoteArtifact = remoteStudyNotesArtifactsResponse.d) != null && (list = studyNoteArtifact.a) != null && (magicNotesArtifactResponse = (MagicNotesArtifactResponse) list.get(0)) != null && (r1 = (R1) ((k) eVar.f).a(magicNotesArtifactResponse)) != null) {
                return r1;
            }
            throw new UpdateTitleException(null);
        } catch (Exception unused) {
            ((org.slf4j.b) eVar.d).m("Unable to update artifact title from remote");
            RemoteStudyNotesArtifactsResponse remoteStudyNotesArtifactsResponse2 = (RemoteStudyNotesArtifactsResponse) apiThreeWrapper.a();
            if (remoteStudyNotesArtifactsResponse2 != null) {
                ModelError modelError = remoteStudyNotesArtifactsResponse2.c;
            }
            throw new UpdateTitleException(null);
        }
    }
}
