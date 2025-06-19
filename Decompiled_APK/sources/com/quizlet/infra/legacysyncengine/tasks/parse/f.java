package com.quizlet.infra.legacysyncengine.tasks.parse;

import com.quizlet.api.model.ApiResponse;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.api.model.PagingInfo;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.base.RelationshipGraph;
import java.util.List;

/* loaded from: classes3.dex */
public final class f {
    public RelationshipGraph a;

    public static PagingInfo a(ApiThreeWrapper apiThreeWrapper) {
        if (apiThreeWrapper.getResponses() == null || apiThreeWrapper.getResponses().size() != 1) {
            return null;
        }
        return ((ApiResponse) apiThreeWrapper.getResponses().get(0)).getPagingInfo();
    }

    public static DBModel b(List list, e eVar) {
        if (list == null) {
            return null;
        }
        int i = eVar.a;
        if (list.size() > i) {
            return (DBModel) list.get(i);
        }
        StringBuilder sbV = android.support.v4.media.session.a.v(i, "Unable to find cached index of ", " given list size of ");
        sbV.append(list.size());
        throw new IllegalStateException(sbV.toString());
    }
}
