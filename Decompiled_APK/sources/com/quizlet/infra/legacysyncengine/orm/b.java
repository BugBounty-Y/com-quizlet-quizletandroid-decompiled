package com.quizlet.infra.legacysyncengine.orm;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3537t4;
import com.google.common.collect.o;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.orm.Filter;
import com.quizlet.db.data.orm.Include;
import com.quizlet.db.data.orm.Relationship;
import java.util.HashSet;
import java.util.Set;
import timber.log.c;

/* loaded from: classes3.dex */
public final class b {
    public final ModelType a;
    public final HashSet b = new HashSet();
    public final HashSet c;

    public b(ModelType modelType) {
        this.a = modelType;
        this.c = new HashSet(modelType.getAutomaticIncludes());
    }

    public final com.quizlet.infra.legacysyncengine.orm.query.a a() {
        return new com.quizlet.infra.legacysyncengine.orm.query.a(this.a, o.n(this.b), this.c);
    }

    public final b b(Long l, ModelField modelField) {
        c(modelField, l == null ? null : AbstractC3537t4.g(l), null);
        return this;
    }

    public final void c(ModelField modelField, Set set, Long l) {
        if (set != null && set.size() == 1) {
            Long l2 = (Long) set.iterator().next();
            if (l2.longValue() < 0) {
                ModelType modelType = this.a;
                if (modelField.equals(ModelIdentityProvider.getSingleIdentityField(modelType))) {
                    c.a.o("Configuring filter with negative id (%s) and non localId field: %s. Should use %s", l2, modelField, "localGeneratedId");
                    modelField = modelType.getLocalIdField();
                }
            }
        }
        this.b.add(l == null ? new Filter(modelField, set) : new a(modelField, set, l));
    }

    public final void d(Relationship relationship, Long l, Long l2) {
        c(relationship, AbstractC3537t4.g(l), l2);
    }

    public final void e(Relationship... relationshipArr) {
        Include include = new Include(relationshipArr);
        ModelType modelType = this.a;
        if (modelType == null || ((Relationship) include.a.get(0)).getFromModelType().equals(modelType)) {
            this.c.add(include);
            return;
        }
        throw new IllegalArgumentException("Include " + include + " does not correspond to model class: " + modelType);
    }
}
