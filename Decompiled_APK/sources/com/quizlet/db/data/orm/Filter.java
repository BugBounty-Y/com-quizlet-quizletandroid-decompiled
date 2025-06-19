package com.quizlet.db.data.orm;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3537t4;
import com.google.common.collect.o;
import com.j256.ormlite.stmt.query.SimpleComparison;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.base.ModelType;
import java.util.HashSet;
import java.util.Set;
import org.apache.commons.lang3.builder.a;
import org.apache.commons.lang3.builder.b;

/* loaded from: classes2.dex */
public class Filter<M extends DBModel> implements Cloneable {
    public final ModelField a;
    public final o b;

    public Filter(Long l, ModelField modelField) {
        this(modelField, AbstractC3537t4.g(l));
    }

    @Override // 
    /* renamed from: b, reason: merged with bridge method [inline-methods] */
    public Filter clone() {
        return new Filter(this.a, new HashSet(this.b));
    }

    public Filter c(Set set) {
        return new Filter(this.a, set);
    }

    public ModelType d(Relationship relationship) {
        return relationship.getToModelType((Long) 0L);
    }

    public void e(ModelField modelField) {
        if (modelField instanceof PolymorphicRelationship) {
            throw new IllegalArgumentException("Polymorphic relationships are not supported. " + modelField);
        }
    }

    public final boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof Filter)) {
            return false;
        }
        Filter filter = (Filter) obj;
        a aVar = new a();
        aVar.a(this.a, filter.a);
        aVar.a(this.b, filter.b);
        return aVar.a;
    }

    public ModelField<M, Long> getField() {
        return this.a;
    }

    public Set<Long> getFieldValues() {
        return this.b;
    }

    public final int hashCode() {
        b bVar = new b(4583, 6337);
        bVar.b(this.a);
        bVar.b(this.b);
        return bVar.b;
    }

    public final String toString() {
        return "(" + this.a + SimpleComparison.EQUAL_TO_OPERATION + this.b + ")";
    }

    public Filter(ModelField modelField, Set set) {
        if (modelField == null) {
            throw new IllegalArgumentException("field must not be null");
        }
        if (set == null) {
            throw new IllegalArgumentException("fieldValues must not be null");
        }
        e(modelField);
        this.a = modelField;
        this.b = o.n(set);
    }
}
