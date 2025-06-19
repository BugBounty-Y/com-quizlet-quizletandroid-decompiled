package com.quizlet.db.data.models.legacy;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import com.quizlet.db.data.models.identity.ModelBackedIdentity;
import com.quizlet.db.data.models.identity.ModelIdentity;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = "favorite_set")
/* loaded from: classes2.dex */
public class LegacyFavoriteSet extends LegacyBaseDBModel {
    public static final String SET_ID_FIELD = "setId";

    @DatabaseField
    private boolean canEdit;

    @DatabaseField(columnName = "id", id = true)
    private Long id;

    @DatabaseField
    private long personId;

    @DatabaseField
    private long setId;

    @DatabaseField
    private int timestamp;

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<LegacyFavoriteSet> getIdentity() {
        return new ModelBackedIdentity(this);
    }
}
