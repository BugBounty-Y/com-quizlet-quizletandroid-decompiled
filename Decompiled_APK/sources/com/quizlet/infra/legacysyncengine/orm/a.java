package com.quizlet.infra.legacysyncengine.orm;

import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.orm.Filter;
import com.quizlet.db.data.orm.PolymorphicRelationship;
import com.quizlet.db.data.orm.Relationship;
import java.util.HashSet;
import java.util.Set;

/* loaded from: classes3.dex */
public final class a extends Filter {
    public final Long c;

    public a(ModelField modelField, Set set, Long l) {
        super(modelField, set);
        this.c = l;
    }

    @Override // com.quizlet.db.data.orm.Filter
    /* renamed from: b */
    public final Filter clone() {
        return new a(this.a, new HashSet(this.b), this.c);
    }

    @Override // com.quizlet.db.data.orm.Filter
    public final Filter c(Set set) {
        return new a(this.a, set, this.c);
    }

    @Override // com.quizlet.db.data.orm.Filter
    public final Object clone() {
        return new a(this.a, new HashSet(this.b), this.c);
    }

    @Override // com.quizlet.db.data.orm.Filter
    public final ModelType d(Relationship relationship) {
        if (this.a.equals(relationship)) {
            return relationship.getToModelType(this.c);
        }
        throw new IllegalArgumentException("Relationship must match field");
    }

    @Override // com.quizlet.db.data.orm.Filter
    public final void e(ModelField modelField) {
        if (modelField instanceof PolymorphicRelationship) {
            return;
        }
        throw new IllegalArgumentException("Only polymorphic relationships are supported. " + modelField);
    }
}
