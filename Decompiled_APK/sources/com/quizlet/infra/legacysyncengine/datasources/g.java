package com.quizlet.infra.legacysyncengine.datasources;

import com.google.common.base.Predicate;
import com.quizlet.db.data.models.persisted.DBGroupMembership;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.db.data.models.persisted.DBStudySet;

/* loaded from: classes3.dex */
public final /* synthetic */ class g implements Predicate {
    public final /* synthetic */ int a;

    @Override // com.google.common.base.Predicate
    public final boolean apply(Object obj) {
        switch (this.a) {
            case 0:
                return ((DBStudySet) obj).getIsCreated();
            case 1:
                DBSession dBSession = (DBSession) obj;
                DBStudySet set = dBSession.getSet();
                return (dBSession.getHidden() || set == null || !set.getIsCreated()) ? false : true;
            default:
                return ((DBGroupMembership) obj).getLevel() >= 1;
        }
    }
}
