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
import com.quizlet.db.data.models.interfaces.FeedItem;
import com.quizlet.db.data.models.interfaces.StudyableModel;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.quizlet.generated.enums.G1;
import com.quizlet.generated.enums.O1;
import java.security.InvalidParameterException;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = "set")
/* loaded from: classes2.dex */
public class DBStudySet extends BaseDBModel implements StudyableModel<DBStudySet>, FeedItem {
    public static final String TABLE_NAME = "set";

    @DatabaseField(columnName = DBStudySetFields.Names.ACCESS_CODE_PREFIX)
    private String accessCodePrefix;

    @DatabaseField
    private int creationSource;

    @DatabaseField(columnName = "creatorId")
    private long creatorId;

    @DatabaseField(columnName = DBStudySetFields.Names.THUMBNAIL_URL)
    private String dThumbnailUrl;

    @DatabaseField(columnName = "_webUrl")
    private String dWebUrl;

    @DatabaseField(columnName = DBStudySetFields.Names.DEFINITION_LANGUAGE)
    private String defLang;

    @DatabaseField
    private String description;

    @DatabaseField(columnName = DBStudySetFields.Names.HAS_DIAGRAMS)
    private boolean hasDiagrams;

    @DatabaseField
    private boolean hasImages;

    @DatabaseField(columnName = "localGeneratedId")
    private long localId;
    private DBUser mCreator;

    @DatabaseField(columnName = DBStudySetFields.Names.MCQ_COUNT)
    @JsonIgnore
    private int mcqCount;

    @DatabaseField(columnName = DBStudySetFields.Names.NUM_TERMS)
    private int numTerms;

    @DatabaseField
    private long parentId;

    @DatabaseField(columnName = DBStudySetFields.Names.PASSWORD)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String password;

    @DatabaseField
    private boolean passwordEdit;

    @DatabaseField
    private boolean passwordUse;

    @DatabaseField
    private int privacyLockStatus;

    @DatabaseField(columnName = DBStudySetFields.Names.PUBLISHED_TIMESTAMP)
    private long publishedTimestamp;

    @DatabaseField(columnName = DBStudySetFields.Names.READY_TO_CREATE)
    private boolean readyToCreate;

    @DatabaseField(columnName = DBStudySetFields.Names.TIMESTAMP)
    private int timestamp;

    @DatabaseField(columnName = "title")
    private String title;

    @DatabaseField(columnName = DBStudySetFields.Names.WORD_LANGUAGE)
    private String wordLang;

    @DatabaseField(columnName = "id", id = true)
    private long id = 0;

    @DatabaseField(columnName = DBStudySetFields.Names.ACCESS_TYPE)
    private int accessType = 0;

    /* renamed from: com.quizlet.db.data.models.persisted.DBStudySet$1, reason: invalid class name */
    public static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$quizlet$generated$enums$TermSide;

        static {
            int[] iArr = new int[O1.values().length];
            $SwitchMap$com$quizlet$generated$enums$TermSide = iArr;
            try {
                iArr[O1.WORD.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$com$quizlet$generated$enums$TermSide[O1.DEFINITION.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$com$quizlet$generated$enums$TermSide[O1.LOCATION.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
        }
    }

    @JsonProperty(DBStudySetFields.Names.ACCESS_CODE_PREFIX)
    public String getAcccessCodePrefix() {
        return this.accessCodePrefix;
    }

    @JsonProperty(DBStudySetFields.Names.ACCESS_TYPE)
    public int getAccessType() {
        return this.accessType;
    }

    public int getCreationSource() {
        return this.creationSource;
    }

    @JsonIgnore
    public DBUser getCreator() {
        return this.mCreator;
    }

    @JsonProperty("creatorId")
    public long getCreatorId() {
        return this.creatorId;
    }

    @Override // com.quizlet.db.data.models.interfaces.StudyableModel
    @JsonProperty("defLang")
    public String getDefLang() {
        return this.defLang;
    }

    public String getDescription() {
        return this.description;
    }

    @Override // com.quizlet.db.data.models.interfaces.FeedItem
    @JsonIgnore
    public Object getFeedId() {
        return Long.valueOf(getId());
    }

    public boolean getHasDiagrams() {
        return this.hasDiagrams;
    }

    @JsonProperty("hasImages")
    public boolean getHasImages() {
        return this.hasImages;
    }

    @JsonIgnore
    public long getId() {
        return this.id;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<DBStudySet> getIdentity() {
        return new ModelBackedIdentity(this);
    }

    @JsonIgnore
    public boolean getIsCreated() {
        if (getDeleted()) {
            return false;
        }
        return getPublishedTimestamp() > 0 || getReadyToCreate();
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
    public String getLanguageCode(O1 o1) {
        int i = AnonymousClass1.$SwitchMap$com$quizlet$generated$enums$TermSide[o1.ordinal()];
        if (i == 1) {
            return getWordLang();
        }
        if (i == 2) {
            return getDefLang();
        }
        if (i == 3) {
            return null;
        }
        throw new InvalidParameterException("Term side does not exist");
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public long getLocalId() {
        return this.localId;
    }

    @JsonIgnore
    @Deprecated
    public int getMcqCount() {
        return this.mcqCount;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelType<DBStudySet> getModelType() {
        return Models.STUDY_SET;
    }

    @JsonProperty("numTerms")
    public int getNumTerms() {
        return this.numTerms;
    }

    public long getParentId() {
        return this.parentId;
    }

    public String getPassword() {
        return this.password;
    }

    @JsonProperty("passwordEdit")
    public boolean getPasswordEdit() {
        return this.passwordEdit;
    }

    @JsonProperty("passwordUse")
    public boolean getPasswordUse() {
        return this.passwordUse;
    }

    public int getPrivacyLockStatus() {
        return this.privacyLockStatus;
    }

    @JsonProperty(DBStudySetFields.Names.PUBLISHED_TIMESTAMP)
    public long getPublishedTimestamp() {
        return this.publishedTimestamp;
    }

    public boolean getReadyToCreate() {
        return this.readyToCreate;
    }

    @Override // com.quizlet.db.data.models.interfaces.FeedItem
    @JsonIgnore
    public DBStudySet getSet() {
        return this;
    }

    @Override // com.quizlet.db.data.models.interfaces.FeedItem
    @JsonIgnore
    public long getSetId() {
        return getId();
    }

    @Override // com.quizlet.db.data.models.interfaces.FeedItem
    @JsonIgnore
    public long getSortTimestamp() {
        return Math.max(getPublishedTimestamp(), getTimestamp());
    }

    @Override // com.quizlet.db.data.models.interfaces.StudyableModel
    @JsonIgnore
    public Long getStudyableId() {
        return Long.valueOf(getId());
    }

    @Override // com.quizlet.db.data.models.interfaces.StudyableModel
    @JsonIgnore
    public G1 getStudyableType() {
        return G1.SET;
    }

    @JsonProperty(DBStudySetFields.Names.THUMBNAIL_URL)
    public String getThumbnailUrl() {
        return this.dThumbnailUrl;
    }

    @JsonProperty("timestamp")
    public long getTimestamp() {
        return this.timestamp;
    }

    @Override // com.quizlet.db.data.models.interfaces.StudyableModel
    public String getTitle() {
        return this.title;
    }

    @JsonProperty("_webUrl")
    public String getWebUrl() {
        return this.dWebUrl;
    }

    @Override // com.quizlet.db.data.models.interfaces.StudyableModel
    @JsonProperty("wordLang")
    public String getWordLang() {
        return this.wordLang;
    }

    @JsonIgnore
    public boolean hasAccessCodePrefix() {
        return false;
    }

    @JsonIgnore
    public boolean isVisibilityRestricted() {
        return this.passwordUse || hasAccessCodePrefix();
    }

    public void setAccessCodePrefix(String str) {
        this.accessCodePrefix = str;
    }

    public void setAccessType(int i) {
        this.accessType = i;
    }

    public void setCreationSource(int i) {
        this.creationSource = i;
    }

    public void setCreator(DBUser dBUser) {
        this.mCreator = dBUser;
    }

    public void setCreatorId(long j) {
        this.creatorId = j;
    }

    public void setDefLang(String str) {
        this.defLang = str;
    }

    public void setDescription(String str) {
        this.description = str;
    }

    public void setHasDiagrams(boolean z) {
        this.hasDiagrams = z;
    }

    public void setHasImages(Boolean bool) {
        this.hasImages = bool.booleanValue();
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

    public void setNumTerms(int i) {
        this.numTerms = i;
    }

    public void setParentId(long j) {
        this.parentId = j;
    }

    public void setPassword(String str) {
        this.password = str;
    }

    public void setPasswordEdit(boolean z) {
        this.passwordEdit = z;
    }

    public void setPasswordUse(boolean z) {
        this.passwordUse = z;
    }

    public void setPrivacyLockStatus(int i) {
        this.privacyLockStatus = i;
    }

    public void setPublishedTimestamp(Long l) {
        this.publishedTimestamp = l.longValue();
    }

    public void setReadyToCreate(boolean z) {
        this.readyToCreate = z;
    }

    public void setThumbnailUrl(String str) {
        this.dThumbnailUrl = str;
    }

    public void setTimestamp(int i) {
        this.timestamp = i;
    }

    public void setTitle(String str) {
        this.title = str;
    }

    public void setWebUrl(String str) {
        this.dWebUrl = str;
    }

    public void setWordLang(String str) {
        this.wordLang = str;
    }
}
