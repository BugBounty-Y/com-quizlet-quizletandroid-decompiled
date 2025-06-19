package com.quizlet.db.billing.model;

import androidx.annotation.Keep;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.j256.ormlite.table.DatabaseTable;
import com.quizlet.db.data.models.base.BaseDBModel;
import com.quizlet.db.data.models.identity.ModelBackedIdentity;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.persisted.base.ModelType;
import org.apache.commons.lang3.builder.b;

@DatabaseTable(tableName = DBSubscription.TABLE_NAME)
@Keep
/* loaded from: classes2.dex */
public class DBSubscription extends BaseDBModel {
    public static final String TABLE_NAME = "subscription";
    public final long expiration;
    public final String providerInformation;
    public final long userId;

    public DBSubscription(@JsonProperty("user_id") long j, @JsonProperty("expiration_timestamp") long j2, @JsonProperty("provider_information") String str) {
        this.userId = j;
        this.expiration = j2;
        this.providerInformation = str;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<DBSubscription> getIdentity() {
        return new ModelBackedIdentity(this);
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public long getLocalId() {
        return 0L;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelType<DBSubscription> getModelType() {
        return null;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel
    public int hashCode() {
        b bVar = new b();
        bVar.a(this.userId);
        bVar.a(this.expiration);
        bVar.b(this.providerInformation);
        return bVar.b;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public void setLocalId(long j) {
    }
}
