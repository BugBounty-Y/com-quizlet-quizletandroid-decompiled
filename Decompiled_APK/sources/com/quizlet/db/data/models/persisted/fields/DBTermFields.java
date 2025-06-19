package com.quizlet.db.data.models.persisted.fields;

import com.quizlet.db.data.models.base.AssociationNames;
import com.quizlet.db.data.models.base.ColumnField;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.persisted.DBImage;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.db.data.orm.SingleRelationship;

/* loaded from: classes2.dex */
public class DBTermFields {
    public static final Relationship<DBTerm, DBImage> DEFINITION_IMAGE;
    public static final ModelField<DBTerm, Long> ID;
    public static final ModelField<DBTerm, Long> LOCAL_ID;
    public static final ModelField<DBTerm, Integer> RANK;
    public static final Relationship<DBTerm, DBStudySet> SET;

    public static final class Names {
        public static final String DEFINITION_AUDIO_URL = "definitionAudio";
        public static final String DEFINITION_CUSTOM_DISTRACTORS = "definitionCustomDistractors";
        public static final String DEFINITION_IMAGE_ID = "definitionImageId";
        public static final String DEFINITION_RICH_TEXT = "definitionRichText";
        public static final String ID = "id";
        public static final String LOCAL_ID = "localGeneratedId";
        public static final String RANK = "orderId";
        public static final String SET_ID = "setId";
        public static final String WORD = "term";
        public static final String WORD_AUDIO_URL = "termAudio";
        public static final String WORD_RICH_TEXT = "wordRichText";
    }

    static {
        ModelType<DBTerm> modelType = Models.TERM;
        LOCAL_ID = new ColumnField<DBTerm, Long>(modelType, "localGeneratedId") { // from class: com.quizlet.db.data.models.persisted.fields.DBTermFields.1
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBTerm dBTerm) {
                return Long.valueOf(dBTerm.getLocalId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBTerm dBTerm, Long l) {
                dBTerm.setLocalId(l.longValue());
            }
        };
        ID = new ColumnField<DBTerm, Long>(modelType, "id") { // from class: com.quizlet.db.data.models.persisted.fields.DBTermFields.2
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBTerm dBTerm) {
                return Long.valueOf(dBTerm.getId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBTerm dBTerm, Long l) {
                dBTerm.setId(l.longValue());
            }
        };
        RANK = new ColumnField<DBTerm, Integer>(modelType, Names.RANK) { // from class: com.quizlet.db.data.models.persisted.fields.DBTermFields.3
            @Override // com.quizlet.db.data.models.base.ModelField
            public Integer getValue(DBTerm dBTerm) {
                return Integer.valueOf(dBTerm.getRank());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBTerm dBTerm, Integer num) {
                dBTerm.setRank(num.intValue());
            }
        };
        SET = new SingleRelationship<DBTerm, DBStudySet>(modelType, "setId", Models.STUDY_SET) { // from class: com.quizlet.db.data.models.persisted.fields.DBTermFields.4
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "set";
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public DBStudySet getModel(DBTerm dBTerm) {
                return dBTerm.getSet();
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBTerm dBTerm) {
                return Long.valueOf(dBTerm.getSetId());
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public void setModel(DBTerm dBTerm, DBStudySet dBStudySet) {
                dBTerm.setSet(dBStudySet);
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBTerm dBTerm, Long l) {
                dBTerm.setSetId(l.longValue());
            }
        };
        DEFINITION_IMAGE = new SingleRelationship<DBTerm, DBImage>(modelType, Names.DEFINITION_IMAGE_ID, Models.IMAGE) { // from class: com.quizlet.db.data.models.persisted.fields.DBTermFields.5
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return AssociationNames.DEFINITION_IMAGE;
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public boolean isRequired() {
                return false;
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public DBImage getModel(DBTerm dBTerm) {
                return dBTerm.getDefinitionImage();
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBTerm dBTerm) {
                return dBTerm.getDefinitionImageId();
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public void setModel(DBTerm dBTerm, DBImage dBImage) {
                dBTerm.setDefinitionImage(dBImage);
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBTerm dBTerm, Long l) {
                dBTerm.setDefinitionImageId(l);
            }
        };
    }
}
