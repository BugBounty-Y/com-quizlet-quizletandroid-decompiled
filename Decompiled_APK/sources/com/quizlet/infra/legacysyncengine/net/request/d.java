package com.quizlet.infra.legacysyncengine.net.request;

import com.google.android.datatransport.cct.internal.s;
import com.onetrust.otpublishers.headless.UI.fragment.q;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import com.quizlet.db.data.orm.Filter;
import com.quizlet.db.data.orm.RequestParameters;
import com.quizlet.db.data.orm.query.IdMappedQuery;
import java.io.PipedOutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import okhttp3.A;

/* loaded from: classes3.dex */
public final class d extends b {
    public final IdMappedQuery j;
    public final int k;
    public final String l;
    public final int m;

    public d(IdMappedQuery idMappedQuery, int i, String str, ExecutionRouter executionRouter, androidx.work.impl.model.c cVar, com.quizlet.infra.legacysyncengine.tasks.parse.f fVar, s sVar, com.squareup.otto.c cVar2, DatabaseHelper databaseHelper) {
        super(idMappedQuery.getModelType(), new ArrayList(), executionRouter, cVar, fVar, sVar, cVar2, databaseHelper);
        this.j = idMappedQuery;
        this.m = 200;
        this.k = i;
        this.l = str;
    }

    @Override // androidx.work.impl.constraints.trackers.e
    public final com.quizlet.infra.legacysyncengine.tasks.parse.g a(PipedOutputStream pipedOutputStream) {
        String endpointRoot;
        IdMappedQuery idMappedQuery = this.j;
        ModelField singleIdentityField = ModelIdentityProvider.getSingleIdentityField(idMappedQuery.getModelType());
        com.google.android.gms.internal.common.g it2 = idMappedQuery.getFilters().iterator();
        while (true) {
            if (!it2.hasNext()) {
                endpointRoot = idMappedQuery.getModelType().getEndpointRoot();
                break;
            }
            Filter filter = (Filter) it2.next();
            if (filter.getField().equals(singleIdentityField)) {
                endpointRoot = idMappedQuery.getModelType().getEndpointRoot() + "/" + org.apache.commons.lang3.e.e(",", filter.getFieldValues());
                break;
            }
        }
        String str = endpointRoot;
        RequestParameters requestParameters = new RequestParameters();
        String str2 = this.l;
        if (str2 != null) {
            requestParameters.a("pagingToken", str2);
            requestParameters.a("page", String.valueOf(this.k));
        }
        requestParameters.a.addAll(idMappedQuery.getApiFiltersAndIncludes().a);
        Iterator it3 = requestParameters.a.iterator();
        while (true) {
            if (!it3.hasNext()) {
                requestParameters.a("perPage", String.valueOf(this.m));
                break;
            }
            if (((String) ((androidx.core.util.c) it3.next()).a).equals("perPage")) {
                break;
            }
        }
        s sVar = (s) this.d;
        return new com.quizlet.infra.legacysyncengine.tasks.parse.i(str, requestParameters, pipedOutputStream, (q) sVar.a, (A) sVar.h);
    }

    @Override // androidx.work.impl.constraints.trackers.e
    public final com.quizlet.infra.legacysyncengine.net.constants.a b() {
        return com.quizlet.infra.legacysyncengine.net.constants.a.b;
    }
}
