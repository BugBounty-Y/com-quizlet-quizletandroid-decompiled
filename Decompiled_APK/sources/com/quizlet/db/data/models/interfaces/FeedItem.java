package com.quizlet.db.data.models.interfaces;

import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.base.ModelType;

/* loaded from: classes2.dex */
public interface FeedItem {
    Object getFeedId();

    ModelType getModelType();

    DBStudySet getSet();

    long getSetId();

    long getSortTimestamp();
}
