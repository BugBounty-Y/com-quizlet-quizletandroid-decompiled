package com.quizlet.db.data.models.persisted;

import android.net.Uri;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.quizlet.data.model.C4115c0;
import com.quizlet.db.data.models.base.BaseDBModel;
import com.quizlet.db.data.models.identity.ModelBackedIdentity;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBImageFields;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import org.apache.commons.lang3.e;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = "image")
/* loaded from: classes2.dex */
public class DBImage extends BaseDBModel {
    private static final int MAX_SMALL_DPI = 270;
    public static final String TABLE_NAME = "image";

    @DatabaseField
    private String code;

    @DatabaseField(columnName = DBImageFields.Names.LARGE_URL)
    private String dLargeUrl;

    @DatabaseField(columnName = DBImageFields.Names.MEDIUM_URL)
    private String dMediumUrl;

    @DatabaseField(columnName = DBImageFields.Names.SMALL_URL)
    private String dSmallUrl;

    @DatabaseField(columnName = DBImageFields.Names.SQUARE_URL)
    private String dSquareUrl;

    @DatabaseField
    private Integer height;

    @DatabaseField(columnName = "id", id = true)
    private long id;

    @DatabaseField(columnName = "localGeneratedId")
    private long localId;

    @DatabaseField(columnName = DBImageFields.Names.LOCAL_PATH)
    private String localPath;

    @DatabaseField
    private Long personId;

    @DatabaseField
    private Long timestamp;

    @DatabaseField
    private Integer width;

    @JsonProperty("code")
    public String getCode() {
        return this.code;
    }

    @JsonIgnore
    public String getDefaultUrl(int i) {
        return i < 270 ? getSquareUrl() : getSmallUrl();
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public List<C4115c0> getFilesForRequest() {
        ArrayList arrayList = new ArrayList(super.getFilesForRequest());
        if (!hasLocalPath()) {
            Intrinsics.checkNotNullParameter(null, "filename");
            Intrinsics.checkNotNullParameter("image[]", "name");
            Intrinsics.checkNotNullParameter(null, "mimeType");
            Intrinsics.checkNotNullParameter(null, "file");
            throw null;
        }
        String uriString = getLocalPath();
        Intrinsics.checkNotNullParameter(uriString, "uriString");
        Uri uri = Uri.parse(uriString);
        Intrinsics.checkNotNullExpressionValue(uri, "parse(...)");
        Intrinsics.checkNotNullParameter(uri, "uri");
        String path = uri.getPath();
        if (path == null) {
            throw new NullPointerException("URI path cannot be null");
        }
        File file = new File(path);
        arrayList.add(new C4115c0(file, file.getName()));
        return arrayList;
    }

    @JsonProperty(OTUXParamsKeys.OT_UX_HEIGHT)
    public Integer getHeight() {
        return this.height;
    }

    @JsonIgnore
    public long getId() {
        return this.id;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<DBImage> getIdentity() {
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

    @JsonIgnore
    public String getLargeUrl() {
        return hasServerUrl() ? getServerLargeUrl() : getLocalPath();
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    @JsonIgnore
    public long getLocalId() {
        return this.localId;
    }

    @JsonProperty(DBImageFields.Names.LOCAL_PATH)
    public String getLocalPath() {
        return this.localPath;
    }

    @JsonIgnore
    public String getMediumUrl() {
        return hasServerUrl() ? getServerMediumUrl() : getLocalPath();
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelType<DBImage> getModelType() {
        return Models.IMAGE;
    }

    @JsonProperty("personId")
    public Long getPersonId() {
        return this.personId;
    }

    @JsonProperty("_secureLegacyUrlLarge")
    public String getServerLargeUrl() {
        return this.dLargeUrl;
    }

    @JsonProperty("_secureLegacyUrl")
    public String getServerMediumUrl() {
        return this.dMediumUrl;
    }

    @JsonProperty("_secureLegacyUrlSmall")
    public String getServerSmallUrl() {
        return this.dSmallUrl;
    }

    @JsonProperty("_secureLegacyUrlSquare")
    public String getServerSquareUrl() {
        return this.dSquareUrl;
    }

    @JsonIgnore
    public String getSmallUrl() {
        return hasServerUrl() ? getServerSmallUrl() : getLocalPath();
    }

    @JsonIgnore
    public String getSquareUrl() {
        return hasServerUrl() ? getServerSquareUrl() : getLocalPath();
    }

    @JsonProperty("timestamp")
    public Long getTimestamp() {
        return this.timestamp;
    }

    @JsonProperty(OTUXParamsKeys.OT_UX_WIDTH)
    public Integer getWidth() {
        return this.width;
    }

    @JsonIgnore
    public boolean hasLocalPath() {
        return e.d(getLocalPath());
    }

    @JsonIgnore
    public boolean hasServerUrl() {
        return e.d(getServerSmallUrl());
    }

    public void setCode(String str) {
        this.code = str;
    }

    public void setHeight(Integer num) {
        this.height = num;
    }

    public void setId(long j) {
        this.id = j;
    }

    public void setJsonId(Long l) {
        this.id = l.longValue();
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public void setLocalId(long j) {
        this.localId = j;
    }

    public void setLocalPath(String str) {
        this.localPath = str;
    }

    public void setPersonId(Long l) {
        this.personId = l;
    }

    public void setServerLargeUrl(String str) {
        this.dLargeUrl = str;
    }

    public void setServerMediumUrl(String str) {
        this.dMediumUrl = str;
    }

    public void setServerSmallUrl(String str) {
        this.dSmallUrl = str;
    }

    public void setServerSquareUrl(String str) {
        this.dSquareUrl = str;
    }

    public void setTimestamp(Long l) {
        this.timestamp = l;
    }

    public void setWidth(Integer num) {
        this.width = num;
    }
}
