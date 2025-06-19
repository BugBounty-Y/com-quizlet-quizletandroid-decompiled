package com.quizlet.db.data.models.legacy;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import com.quizlet.db.data.models.identity.ModelBackedIdentity;
import com.quizlet.db.data.models.identity.ModelIdentity;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = "group_wrapper")
/* loaded from: classes2.dex */
public class LegacyGroupWrapper extends LegacyBaseDBModel {
    private static final String USERNAME_FIELD = "username";

    @DatabaseField
    private String groupIds;

    @DatabaseField(columnName = "username", id = true)
    private String username;

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<LegacyGroupWrapper> getIdentity() {
        return new ModelBackedIdentity(this);
    }
}
