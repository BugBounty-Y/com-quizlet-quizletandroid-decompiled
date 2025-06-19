package com.quizlet.db.data.models.legacy;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import com.quizlet.db.data.models.identity.ModelBackedIdentity;
import com.quizlet.db.data.models.identity.ModelIdentity;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = "legacy_group_membership")
/* loaded from: classes2.dex */
public class LegacyGroupMembership extends LegacyBaseDBModel {
    private static final String GROUP_ID_FIELD = "groupId";
    private static final String MEMBERSHIP_ID_FIELD = "membershipId";

    @DatabaseField
    private boolean emailNotification;

    @DatabaseField(columnName = "groupId")
    private Long groupId;

    @DatabaseField(columnName = MEMBERSHIP_ID_FIELD, id = true)
    private Long membershipId;

    @DatabaseField
    private String profileImage;

    @DatabaseField
    private String role;

    @DatabaseField
    private String username;

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<LegacyGroupMembership> getIdentity() {
        return new ModelBackedIdentity(this);
    }
}
