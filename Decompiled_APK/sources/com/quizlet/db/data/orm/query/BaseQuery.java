package com.quizlet.db.data.orm.query;

import com.google.android.gms.internal.common.g;
import com.google.common.collect.o;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.orm.Filter;
import com.quizlet.db.data.orm.Include;
import com.quizlet.db.data.orm.RequestParameters;
import java.util.Iterator;
import java.util.Set;
import org.apache.commons.lang3.builder.a;
import org.apache.commons.lang3.builder.b;
import org.apache.commons.lang3.e;

/* loaded from: classes2.dex */
public abstract class BaseQuery<M extends DBModel> {
    private static final String API_3_LIST_PARAMETER_DELIMITER = ",";
    private static final String FILTERS = "filters";
    public final ModelType a;
    public final o b;
    public final Set c;

    public BaseQuery(ModelType modelType, o oVar, Set set) {
        this.a = modelType;
        this.b = oVar;
        this.c = set;
    }

    public final boolean a(DBModel dBModel) {
        if (getModelType() != dBModel.getModelType() || getFilters() == null || getFilters().size() == 0) {
            return false;
        }
        g it2 = getFilters().iterator();
        while (it2.hasNext()) {
            Filter filter = (Filter) it2.next();
            if (!filter.getFieldValues().contains((Long) filter.a.getValue(dBModel))) {
                return false;
            }
        }
        Set set = this.c;
        if (set == null) {
            return true;
        }
        Iterator it3 = set.iterator();
        while (it3.hasNext()) {
            if (!Include.b(dBModel, ((Include) it3.next()).a)) {
                return false;
            }
        }
        return true;
    }

    public final boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof BaseQuery)) {
            return false;
        }
        BaseQuery baseQuery = (BaseQuery) obj;
        a aVar = new a();
        aVar.a(this.b, baseQuery.b);
        aVar.a(this.c, baseQuery.c);
        aVar.a(this.a, baseQuery.a);
        return aVar.a;
    }

    public boolean getAnyFilterValueNegative() {
        o oVar = this.b;
        if (oVar == null) {
            return false;
        }
        g it2 = oVar.iterator();
        while (it2.hasNext()) {
            Iterator<Long> it3 = ((Filter) it2.next()).getFieldValues().iterator();
            while (it3.hasNext()) {
                if (it3.next().longValue() < 0) {
                    return true;
                }
            }
        }
        return false;
    }

    public RequestParameters getApiFiltersAndIncludes() {
        RequestParameters requestParameters = new RequestParameters();
        Set<Include> set = this.c;
        if (set != null) {
            for (Include include : set) {
                requestParameters.a(include.getJsonKey(), include.getJsonValue());
            }
        }
        g it2 = this.b.iterator();
        while (it2.hasNext()) {
            Filter filter = (Filter) it2.next();
            requestParameters.a("filters[" + filter.getField().getAPIFieldName() + "]", e.e(API_3_LIST_PARAMETER_DELIMITER, filter.getFieldValues()));
        }
        return requestParameters;
    }

    public o getFilters() {
        return this.b;
    }

    public Set<Include> getIncludes() {
        return this.c;
    }

    public ModelType<M> getModelType() {
        return this.a;
    }

    public final int hashCode() {
        b bVar = new b(1093, 821);
        bVar.b(this.b);
        bVar.b(this.c);
        bVar.b(this.a);
        return bVar.b;
    }

    public final String toString() {
        return "Query(" + this.b + " for model " + this.a + ", " + getApiFiltersAndIncludes() + ")";
    }
}
