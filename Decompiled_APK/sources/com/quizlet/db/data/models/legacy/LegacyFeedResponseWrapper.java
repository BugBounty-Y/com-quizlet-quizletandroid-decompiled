package com.quizlet.db.data.models.legacy;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import com.quizlet.db.data.models.identity.ModelBackedIdentity;
import com.quizlet.db.data.models.identity.ModelIdentity;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = "feed_response_wrapper")
/* loaded from: classes2.dex */
public class LegacyFeedResponseWrapper extends LegacyBaseDBModel {
    private static final String URL_FIELD = "url";

    @DatabaseField(columnName = "url", id = true)
    private String url;

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<LegacyFeedResponseWrapper> getIdentity() {
        return new ModelBackedIdentity(this);
    }
}
