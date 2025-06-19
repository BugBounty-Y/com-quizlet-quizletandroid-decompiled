package com.quizlet.db.data.models.legacy;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import com.quizlet.db.data.models.identity.ModelBackedIdentity;
import com.quizlet.db.data.models.identity.ModelIdentity;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = "legacy_session")
/* loaded from: classes2.dex */
public class LegacySession extends LegacyBaseDBModel {

    @DatabaseField
    private Integer finishDate;

    @DatabaseField
    private String formattedScore;

    @DatabaseField(columnName = "id", id = true)
    private Long id;

    @DatabaseField
    private String imageUrl;

    @DatabaseField
    private String mode;

    @DatabaseField
    private Long setId;

    @DatabaseField
    private Integer startDate;

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<LegacySession> getIdentity() {
        return new ModelBackedIdentity(this);
    }
}
