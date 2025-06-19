package com.quizlet.baserecyclerview.decoration;

import androidx.collection.C0219q;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3525r4;
import com.google.common.base.Function;
import com.quizlet.api.model.ApiResponse;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.api.model.ModelError;
import com.quizlet.api.model.ModelWrapper;
import com.quizlet.db.billing.model.DBSubscription;
import com.quizlet.db.data.models.persisted.DBGroupMembership;
import com.quizlet.db.data.models.persisted.DBGroupSet;
import com.quizlet.db.data.models.persisted.DBSelectedTerm;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.eventlogger.EventLogUploader;
import com.quizlet.infra.legacysyncengine.datasources.o;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.functions.i;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import retrofit2.K;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements b, h, Function, i, io.reactivex.rxjava3.functions.b {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object obj, Object obj2) {
        com.quizlet.infra.legacysyncengine.net.request.c cVar = (com.quizlet.infra.legacysyncengine.net.request.c) obj;
        com.quizlet.infra.legacysyncengine.net.request.c cVar2 = (com.quizlet.infra.legacysyncengine.net.request.c) obj2;
        switch (this.a) {
            case 18:
                return new com.quizlet.infra.legacysyncengine.net.request.c(com.facebook.appevents.codeless.i.g(cVar.a, cVar2.a));
            default:
                return new com.quizlet.infra.legacysyncengine.net.request.c(com.facebook.appevents.codeless.i.g(cVar.a, cVar2.a));
        }
    }

    @Override // io.reactivex.rxjava3.functions.i
    public boolean test(Object obj) {
        switch (this.a) {
            case 8:
                return !((List) obj).isEmpty();
            case 9:
                return !((List) obj).isEmpty();
            case 12:
                return ((DBStudySet) obj).getIsCreated();
            case 15:
                DBSession dBSession = (DBSession) obj;
                return (dBSession.getHidden() || dBSession.getSet() == null || !dBSession.getSet().getIsCreated()) ? false : true;
            case EventType.WINDOW_STATE /* 22 */:
                return ((Boolean) obj).booleanValue();
            default:
                return !((List) obj).isEmpty();
        }
    }

    @Override // com.quizlet.baserecyclerview.decoration.b
    public boolean z(int i) {
        return true;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        Throwable illegalStateException;
        switch (this.a) {
            case 1:
                return (ApiThreeWrapper) ((K) obj).b;
            case 2:
                return (ApiResponse) ((ApiThreeWrapper) obj).getResponses().get(0);
            case 3:
                ApiResponse apiResponse = (ApiResponse) obj;
                ModelWrapper modelWrapper = apiResponse.getModelWrapper();
                if (apiResponse.hasError()) {
                    ModelError error = apiResponse.getError();
                    illegalStateException = new Throwable(String.format("Subscription api error occurred: code = %d, message = %s", error.getCode(), error.getServerMessage()));
                } else {
                    illegalStateException = (modelWrapper == null || modelWrapper.getSubscriptions() == null || modelWrapper.getSubscriptions().isEmpty() || modelWrapper.getUsers() == null || modelWrapper.getUsers().isEmpty()) ? new IllegalStateException("Server error: subscription upgrade error/empty body") : null;
                }
                if (illegalStateException != null) {
                    return new com.quizlet.billing.subscriptions.b(illegalStateException);
                }
                List<DBSubscription> subscriptions = modelWrapper.getSubscriptions();
                List<DBUser> users = modelWrapper.getUsers();
                subscriptions.get(0);
                return new com.quizlet.billing.subscriptions.b(users.get(0));
            case 4:
                Throwable it2 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return Boolean.FALSE;
            case 5:
                return android.support.v4.media.session.a.B("[", ((Relationship) obj).getApiAssociationName(), "]");
            case 6:
                EventLogUploader.LogUploadResult logUploadResult = (EventLogUploader.LogUploadResult) obj;
                EventLogUploader.c(logUploadResult);
                return logUploadResult;
            case 7:
                return ((o) obj).d();
            case 8:
            case 9:
            case 10:
            case 12:
            case 15:
            case 18:
            case 19:
            case EventType.WINDOW_STATE /* 22 */:
            default:
                Iterator it3 = ((List) obj).iterator();
                Object next = it3.next();
                if (!it3.hasNext()) {
                    return (DBUser) next;
                }
                StringBuilder sb = new StringBuilder("expected one element but was: <");
                sb.append(next);
                for (int i = 0; i < 4 && it3.hasNext(); i++) {
                    sb.append(", ");
                    sb.append(it3.next());
                }
                if (it3.hasNext()) {
                    sb.append(", ...");
                }
                sb.append('>');
                throw new IllegalArgumentException(sb.toString());
            case 11:
                return (List) obj;
            case 13:
                return Long.valueOf(((DBStudySet) obj).getSetId());
            case 14:
                return new HashSet((List) obj);
            case 16:
                return Long.valueOf(((DBSession) obj).getSetId());
            case 17:
                return ((DBSession) obj).getSet();
            case 20:
                List<DBSelectedTerm> list = (List) obj;
                C0219q c0219q = new C0219q(list.size());
                for (DBSelectedTerm dBSelectedTerm : list) {
                    c0219q.g(dBSelectedTerm.getTermId(), dBSelectedTerm);
                }
                return c0219q;
            case 21:
                List list2 = (List) obj;
                return Boolean.valueOf(list2.size() > 0 && list2.size() != 200);
            case EventType.AUDIO /* 23 */:
                return Long.valueOf(((DBGroupMembership) obj).getClassId());
            case EventType.VIDEO /* 24 */:
                return AbstractC3525r4.e((List) obj, new a(27));
            case EventType.SUBS /* 25 */:
                return Long.valueOf(((DBGroupMembership) obj).getClassId());
            case EventType.CDN /* 26 */:
                return ((DBGroupSet) obj).getSet();
            case 27:
                return Long.valueOf(((DBGroupSet) obj).getSetId());
        }
    }
}
