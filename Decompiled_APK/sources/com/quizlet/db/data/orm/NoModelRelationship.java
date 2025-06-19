package com.quizlet.db.data.orm;

import com.quizlet.db.data.models.base.DBModel;

/* loaded from: classes2.dex */
public abstract class NoModelRelationship<F extends DBModel, T extends DBModel> extends SingleRelationship<F, T> {
    @Override // com.quizlet.db.data.orm.Relationship
    public final T getModel(F f) {
        return null;
    }

    @Override // com.quizlet.db.data.orm.Relationship
    public final boolean hasModelReference() {
        return false;
    }

    @Override // com.quizlet.db.data.orm.Relationship
    public final void setModel(F f, T t) {
    }
}
