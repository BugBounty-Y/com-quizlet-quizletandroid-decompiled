package com.quizlet.db.data.models.persisted;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import com.quizlet.db.data.models.base.BaseDBModel;
import com.quizlet.db.data.models.identity.ModelBackedIdentity;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import org.apache.commons.lang3.e;
import org.jetbrains.annotations.NotNull;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = "school")
/* loaded from: classes2.dex */
public class DBSchool extends BaseDBModel {
    public static final String TABLE_NAME = "school";

    @DatabaseField
    String city;

    @DatabaseField
    String country;

    @DatabaseField(columnName = "id", id = true)
    long id;

    @DatabaseField
    double latitude;

    @DatabaseField(columnName = "localGeneratedId")
    private long localId;

    @DatabaseField
    double longitude;

    @DatabaseField
    String name;

    @DatabaseField
    String state;

    public String getCity() {
        return this.city;
    }

    public String getCountry() {
        return this.country;
    }

    @JsonIgnore
    public long getId() {
        return this.id;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<DBSchool> getIdentity() {
        return new ModelBackedIdentity(this);
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("id")
    public Long getJsonId() {
        long j = this.id;
        if (j > 0) {
            return Long.valueOf(j);
        }
        return null;
    }

    public double getLatitude() {
        return this.latitude;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public long getLocalId() {
        return this.localId;
    }

    public double getLongitude() {
        return this.longitude;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelType<DBSchool> getModelType() {
        return Models.SCHOOL;
    }

    public String getName() {
        return this.name;
    }

    @NotNull
    public String getSchoolString() {
        StringBuilder sb = new StringBuilder();
        String str = this.name;
        String strTrim = str == null ? "" : str.trim();
        sb.append(strTrim);
        if (e.d(strTrim) && e.d(this.city)) {
            sb.append(" • ");
        }
        if (e.d(this.city)) {
            sb.append(this.city.trim());
        }
        return sb.toString();
    }

    public String getState() {
        return this.state;
    }

    @JsonProperty("city")
    public void setCity(String str) {
        this.city = str;
    }

    public void setCountry(String str) {
        this.country = str;
    }

    public void setId(long j) {
        this.id = j;
    }

    public void setJsonId(Long l) {
        this.id = l.longValue();
    }

    public void setLatitude(double d) {
        this.latitude = d;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public void setLocalId(long j) {
        this.localId = j;
    }

    public void setLongitude(double d) {
        this.longitude = d;
    }

    public void setName(String str) {
        this.name = str;
    }

    @JsonProperty("state")
    public void setState(String str) {
        this.state = str;
    }
}
