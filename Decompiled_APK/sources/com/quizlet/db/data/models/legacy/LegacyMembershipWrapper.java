package com.quizlet.db.data.models.legacy;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.j256.ormlite.field.DatabaseField;
import com.quizlet.db.data.models.identity.ModelBackedIdentity;
import com.quizlet.db.data.models.identity.ModelIdentity;

@JsonIgnoreProperties(ignoreUnknown = true)
/* loaded from: classes2.dex */
public class LegacyMembershipWrapper extends LegacyBaseDBModel {
    private static final String GROUP_ID_FIELD = "groupId";

    @DatabaseField(columnName = "groupId", id = true)
    private Long groupId;

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<LegacyMembershipWrapper> getIdentity() {
        return new ModelBackedIdentity(this);
    }
}
