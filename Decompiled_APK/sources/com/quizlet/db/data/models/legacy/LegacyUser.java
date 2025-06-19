package com.quizlet.db.data.models.legacy;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import com.quizlet.db.data.models.identity.ModelBackedIdentity;
import com.quizlet.db.data.models.identity.ModelIdentity;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = "legacy_user")
/* loaded from: classes2.dex */
public class LegacyUser extends LegacyBaseDBModel {
    public static final String USERNAME_FIELD = "username";

    @DatabaseField
    private boolean isTeacher;

    @DatabaseField
    private boolean locked;

    @DatabaseField
    private String profileImage;

    @DatabaseField
    private int signUpDate;

    @DatabaseField(columnName = "username", id = true)
    private String username;

    @DatabaseField(columnName = "id")
    private long id = 0;

    @DatabaseField
    private String language = "en";

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<LegacyUser> getIdentity() {
        return new ModelBackedIdentity(this);
    }
}
