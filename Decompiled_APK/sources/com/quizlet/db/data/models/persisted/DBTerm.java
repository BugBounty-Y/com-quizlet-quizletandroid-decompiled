package com.quizlet.db.data.models.persisted;

import androidx.annotation.NonNull;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import com.quizlet.db.data.models.base.BaseDBModel;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.identity.ModelBackedIdentity;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBTermFields;
import com.quizlet.db.data.models.wrappers.RawJsonObject;
import com.quizlet.db.util.RawJsonDeserializer;
import com.quizlet.db.util.RawJsonSerializer;
import com.quizlet.generated.enums.O1;
import java.security.InvalidParameterException;
import org.apache.commons.lang3.e;
import timber.log.c;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = "term")
/* loaded from: classes2.dex */
public class DBTerm extends BaseDBModel {
    public static final String TABLE_NAME = "term";

    @DatabaseField(columnName = DBTermFields.Names.DEFINITION_AUDIO_URL)
    private String _definitionAudioUrl;

    @DatabaseField(columnName = DBTermFields.Names.DEFINITION_CUSTOM_DISTRACTORS)
    @JsonIgnore
    private String _definitionCustomDistractors;

    @DatabaseField(columnName = DBTermFields.Names.DEFINITION_RICH_TEXT)
    @JsonIgnore
    private String _definitionRichText;

    @DatabaseField
    private String _definitionTtsUrl;

    @DatabaseField(columnName = DBTermFields.Names.WORD_AUDIO_URL)
    private String _wordAudioUrl;

    @DatabaseField(columnName = DBTermFields.Names.WORD_RICH_TEXT)
    @JsonIgnore
    private String _wordRichText;

    @DatabaseField
    private String _wordTtsUrl;

    @DatabaseField
    private String definition;

    @DatabaseField
    private Long definitionCustomAudioId;

    @JsonProperty(DBTermFields.Names.DEFINITION_CUSTOM_DISTRACTORS)
    @JsonDeserialize(using = RawJsonDeserializer.class)
    @JsonSerialize(using = RawJsonSerializer.class)
    private RawJsonObject definitionCustomDistractors;
    private DBImage definitionImage;

    @DatabaseField(columnName = DBTermFields.Names.DEFINITION_IMAGE_ID)
    private Long definitionImageId;

    @JsonProperty(DBTermFields.Names.DEFINITION_RICH_TEXT)
    @JsonDeserialize(using = RawJsonDeserializer.class)
    @JsonSerialize(using = RawJsonSerializer.class)
    private RawJsonObject definitionRichText;

    @DatabaseField(columnName = "id", id = true)
    private long id;

    @DatabaseField
    @JsonIgnore
    private String imageUrl;
    private boolean isPlaying;

    @DatabaseField(columnName = "localGeneratedId")
    private long localId;
    protected DBStudySet mSet;

    @DatabaseField(columnName = DBTermFields.Names.RANK)
    private int rank = -1;

    @DatabaseField(columnName = "setId")
    private long setId;

    @DatabaseField(columnName = "term")
    private String word;

    @DatabaseField
    private Long wordCustomAudioId;

    @JsonProperty(DBTermFields.Names.WORD_RICH_TEXT)
    @JsonDeserialize(using = RawJsonDeserializer.class)
    @JsonSerialize(using = RawJsonSerializer.class)
    private RawJsonObject wordRichText;

    /* renamed from: com.quizlet.db.data.models.persisted.DBTerm$1, reason: invalid class name */
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

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public <M extends DBModel> int compare(@NonNull M m, @NonNull M m2) {
        if (!(m instanceof DBTerm) || !(m2 instanceof DBTerm)) {
            return super.compare(m, m2);
        }
        DBTerm dBTerm = (DBTerm) m;
        DBTerm dBTerm2 = (DBTerm) m2;
        int iCompareTo = Integer.valueOf(dBTerm.getRank()).compareTo(Integer.valueOf(dBTerm2.getRank()));
        return iCompareTo == 0 ? Long.valueOf(dBTerm.getId()).compareTo(Long.valueOf(dBTerm2.getId())) * (-1) : iCompareTo;
    }

    @JsonIgnore
    public String getAudioUrl(O1 o1) {
        int i = AnonymousClass1.$SwitchMap$com$quizlet$generated$enums$TermSide[o1.ordinal()];
        if (i == 1) {
            return getWordAudioUrl();
        }
        if (i == 2) {
            return getDefinitionAudioUrl();
        }
        if (i == 3) {
            return null;
        }
        throw new InvalidParameterException("Term side does not exist");
    }

    public String getDefinition() {
        return this.definition;
    }

    @JsonProperty("_definitionAudioUrl")
    public String getDefinitionAudioUrl() {
        return this._definitionAudioUrl;
    }

    public Long getDefinitionCustomAudioId() {
        return this.definitionCustomAudioId;
    }

    public RawJsonObject getDefinitionCustomDistractors() {
        RawJsonObject rawJsonObject = this.definitionCustomDistractors;
        return rawJsonObject == null ? new RawJsonObject(this._definitionCustomDistractors) : rawJsonObject;
    }

    @JsonIgnore
    public DBImage getDefinitionImage() {
        return this.definitionImage;
    }

    @JsonProperty("definitionImageCode")
    public String getDefinitionImageCode() {
        DBImage dBImage = this.definitionImage;
        if (dBImage != null) {
            return dBImage.getCode();
        }
        return null;
    }

    public String getDefinitionImageDefaultUrl(int i) {
        if (getDefinitionImage() != null) {
            return getDefinitionImage().getDefaultUrl(i);
        }
        return null;
    }

    @JsonInclude(JsonInclude.Include.ALWAYS)
    public Long getDefinitionImageId() {
        return this.definitionImageId;
    }

    @JsonIgnore
    public String getDefinitionImageLargeUrl() {
        if (getDefinitionImage() != null) {
            return getDefinitionImage().getMediumUrl();
        }
        return null;
    }

    @JsonIgnore
    public String getDefinitionImageSmallUrl() {
        if (getDefinitionImage() != null) {
            return getDefinitionImage().getSquareUrl();
        }
        return null;
    }

    @JsonIgnore
    public String getDefinitionImageUrl() {
        return getDefinitionImage() != null ? getDefinitionImage().getSmallUrl() : getLegacyDefinitionImageUrl();
    }

    public RawJsonObject getDefinitionRichText() {
        RawJsonObject rawJsonObject = this.definitionRichText;
        return rawJsonObject == null ? new RawJsonObject(this._definitionRichText) : rawJsonObject;
    }

    public String getDefinitionTtsUrl() {
        return this._definitionTtsUrl;
    }

    @JsonIgnore
    public long getId() {
        return this.id;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelIdentity<DBTerm> getIdentity() {
        return new ModelBackedIdentity(this);
    }

    public boolean getIsPlaying() {
        return this.isPlaying;
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
        DBStudySet dBStudySet = this.mSet;
        if (dBStudySet != null) {
            return dBStudySet.getLanguageCode(o1);
        }
        c.a(new RuntimeException("Cannot find term side for null set"));
        return null;
    }

    @JsonProperty("_imageUrl")
    @Deprecated
    public String getLegacyDefinitionImageUrl() {
        return this.imageUrl;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public long getLocalId() {
        return this.localId;
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public ModelType<DBTerm> getModelType() {
        return Models.TERM;
    }

    public int getRank() {
        return this.rank;
    }

    @JsonIgnore
    public String getRichText(O1 o1) {
        int i = AnonymousClass1.$SwitchMap$com$quizlet$generated$enums$TermSide[o1.ordinal()];
        if (i == 1) {
            if (getWordRichText() != null) {
                return getWordRichText().getValue();
            }
            return null;
        }
        if (i != 2) {
            if (i == 3) {
                return null;
            }
            throw new InvalidParameterException("Term side does not exist");
        }
        if (getDefinitionRichText() != null) {
            return getDefinitionRichText().getValue();
        }
        return null;
    }

    @JsonIgnore
    public DBStudySet getSet() {
        return this.mSet;
    }

    public long getSetId() {
        return this.setId;
    }

    @JsonIgnore
    public String getText(O1 o1) {
        int i = AnonymousClass1.$SwitchMap$com$quizlet$generated$enums$TermSide[o1.ordinal()];
        if (i == 1) {
            return getWord();
        }
        if (i == 2) {
            return getDefinition();
        }
        if (i == 3) {
            return null;
        }
        throw new InvalidParameterException("Term side does not exist");
    }

    @JsonProperty("word")
    public String getWord() {
        return this.word;
    }

    @JsonProperty("_wordAudioUrl")
    public String getWordAudioUrl() {
        return this._wordAudioUrl;
    }

    public Long getWordCustomAudioId() {
        return this.wordCustomAudioId;
    }

    public RawJsonObject getWordRichText() {
        RawJsonObject rawJsonObject = this.wordRichText;
        return rawJsonObject == null ? new RawJsonObject(this._wordRichText) : rawJsonObject;
    }

    public String getWordTtsUrl() {
        return this._wordTtsUrl;
    }

    public boolean hasDefinitionAudio() {
        return this._definitionAudioUrl != null;
    }

    public boolean hasDefinitionImage() {
        Long l = this.definitionImageId;
        return (l == null || l.longValue() == 0) ? false : true;
    }

    @JsonIgnore
    public boolean hasRichText() {
        return (this._definitionRichText == null && this._wordRichText == null) ? false : true;
    }

    public boolean hasValidUserContent() {
        if (e.b(this.word)) {
            return false;
        }
        return !e.b(this.definition) || hasDefinitionImage();
    }

    public boolean hasWordAudio() {
        return this._wordAudioUrl != null;
    }

    public boolean isIncomplete() {
        return e.d(this.word) ^ e.d(this.definition);
    }

    public void setDefinition(String str) {
        this.definition = str;
    }

    public void setDefinitionAudioUrl(String str) {
        this._definitionAudioUrl = str;
    }

    public void setDefinitionCustomAudioId(Long l) {
        this.definitionCustomAudioId = l;
    }

    public void setDefinitionCustomDistractors(RawJsonObject rawJsonObject) {
        this.definitionCustomDistractors = rawJsonObject;
        if (rawJsonObject != null) {
            this._definitionCustomDistractors = rawJsonObject.getValue();
        }
    }

    @JsonIgnore
    public void setDefinitionImage(DBImage dBImage) {
        this.definitionImage = dBImage;
    }

    public void setDefinitionImageId(Long l) {
        this.definitionImageId = l;
    }

    public void setDefinitionRichText(RawJsonObject rawJsonObject) {
        this.definitionRichText = rawJsonObject;
        if (rawJsonObject != null) {
            this._definitionRichText = rawJsonObject.getValue();
        }
    }

    public void setDefinitionTtsUrl(String str) {
        this._definitionTtsUrl = str;
    }

    public void setId(long j) {
        this.id = j;
    }

    public void setImageUrl(String str) {
        this.imageUrl = str;
    }

    public void setIsPlaying(boolean z) {
        this.isPlaying = z;
    }

    public void setJsonId(Long l) {
        this.id = l.longValue();
    }

    @Override // com.quizlet.db.data.models.base.BaseDBModel, com.quizlet.db.data.models.base.DBModel
    public void setLocalId(long j) {
        this.localId = j;
    }

    @JsonProperty("rank")
    public void setRank(int i) {
        this.rank = i;
    }

    @JsonIgnore
    public void setSet(DBStudySet dBStudySet) {
        this.mSet = dBStudySet;
    }

    public void setSetId(long j) {
        this.setId = j;
    }

    public void setWord(String str) {
        this.word = str;
    }

    public void setWordAudioUrl(String str) {
        this._wordAudioUrl = str;
    }

    public void setWordCustomAudioId(Long l) {
        this.wordCustomAudioId = l;
    }

    public void setWordRichText(RawJsonObject rawJsonObject) {
        this.wordRichText = rawJsonObject;
        if (rawJsonObject != null) {
            this._wordRichText = rawJsonObject.getValue();
        }
    }

    public void setWordTtsUrl(String str) {
        this._wordTtsUrl = str;
    }
}
