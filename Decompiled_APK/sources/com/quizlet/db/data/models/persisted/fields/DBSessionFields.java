package com.quizlet.db.data.models.persisted.fields;

import com.quizlet.db.data.models.base.ColumnField;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.interfaces.StudyableModel;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.base.StudyableModelTypes;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.quizlet.db.data.orm.NoModelRelationship;
import com.quizlet.db.data.orm.PolymorphicRelationship;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.generated.enums.G1;
import java.util.Locale;
import timber.log.c;

/* loaded from: classes2.dex */
public class DBSessionFields {
    public static final ModelField<DBSession, Long> ENDED_TIMESTAMP;
    public static final ModelField<DBSession, Long> ID;
    public static final ModelField<DBSession, Long> ITEM_TYPE;
    public static final ModelField<DBSession, Long> LOCAL_ID;
    public static final ModelField<DBSession, Long> MODE_TYPE;
    public static final Relationship<DBSession, DBUser> PERSON;
    public static final ModelField<DBSession, Boolean> SELECTED_TERMS_ONLY;
    public static final Relationship<DBSession, StudyableModel> STUDYABLE;
    public static final ModelField<DBSession, Long> TIMESTAMP;

    /* renamed from: com.quizlet.db.data.models.persisted.fields.DBSessionFields$10, reason: invalid class name */
    public static /* synthetic */ class AnonymousClass10 {
        static final /* synthetic */ int[] $SwitchMap$com$quizlet$generated$enums$StudyableType;

        static {
            int[] iArr = new int[G1.values().length];
            $SwitchMap$com$quizlet$generated$enums$StudyableType = iArr;
            try {
                iArr[G1.SET.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$com$quizlet$generated$enums$StudyableType[G1.FOLDER.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
        }
    }

    public static final class Names {
        public static final String ENDED_TIMESTAMP = "endTimestamp";
        public static final String ID = "id";
        public static final String ITEM_ID = "itemId";
        public static final String ITEM_TYPE = "itemType";
        public static final String LOCAL_ID = "localGeneratedId";
        public static final String MODE_TYPE = "mode";
        public static final String PERSON_ID = "personId";
        public static final String SCORE = "score";
        public static final String SELECTED_TERMS_ONLY = "selectedOnly";
        public static final String TIMESTAMP = "startTimestamp";
    }

    static {
        ModelType<DBSession> modelType = Models.SESSION;
        LOCAL_ID = new ColumnField<DBSession, Long>(modelType, "localGeneratedId") { // from class: com.quizlet.db.data.models.persisted.fields.DBSessionFields.1
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBSession dBSession) {
                return Long.valueOf(dBSession.getLocalId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBSession dBSession, Long l) {
                dBSession.setLocalId(l.longValue());
            }
        };
        ID = new ColumnField<DBSession, Long>(modelType, "id") { // from class: com.quizlet.db.data.models.persisted.fields.DBSessionFields.2
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBSession dBSession) {
                return Long.valueOf(dBSession.getId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBSession dBSession, Long l) {
                dBSession.setId(l);
            }
        };
        TIMESTAMP = new ColumnField<DBSession, Long>(modelType, "startTimestamp") { // from class: com.quizlet.db.data.models.persisted.fields.DBSessionFields.3
            @Override // com.quizlet.db.data.models.base.ModelField
            public String getAPIFieldName() {
                return "timestamp";
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBSession dBSession) {
                return Long.valueOf(dBSession.getTimestampMs());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBSession dBSession, Long l) {
                dBSession.setTimestampMs(l.longValue());
            }
        };
        ENDED_TIMESTAMP = new ColumnField<DBSession, Long>(modelType, Names.ENDED_TIMESTAMP) { // from class: com.quizlet.db.data.models.persisted.fields.DBSessionFields.4
            @Override // com.quizlet.db.data.models.base.ModelField
            public String getAPIFieldName() {
                return "endedTimestamp";
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBSession dBSession) {
                return Long.valueOf(dBSession.getEndedTimestampMs());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBSession dBSession, Long l) {
                dBSession.setEndedTimestampMs(l.longValue());
            }
        };
        ITEM_TYPE = new ColumnField<DBSession, Long>(modelType, Names.ITEM_TYPE) { // from class: com.quizlet.db.data.models.persisted.fields.DBSessionFields.5
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBSession dBSession) {
                return Long.valueOf(dBSession.getItemType());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBSession dBSession, Long l) {
                dBSession.setItemType(l.intValue());
            }
        };
        MODE_TYPE = new ColumnField<DBSession, Long>(modelType, "mode") { // from class: com.quizlet.db.data.models.persisted.fields.DBSessionFields.6
            @Override // com.quizlet.db.data.models.base.ModelField
            public String getAPIFieldName() {
                return DBUserFields.Names.USER_UPGRADE_TYPE;
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBSession dBSession) {
                return Long.valueOf(dBSession.getType());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBSession dBSession, Long l) {
                dBSession.setType(l.intValue());
            }
        };
        SELECTED_TERMS_ONLY = new ColumnField<DBSession, Boolean>(modelType, Names.SELECTED_TERMS_ONLY) { // from class: com.quizlet.db.data.models.persisted.fields.DBSessionFields.7
            @Override // com.quizlet.db.data.models.base.ModelField
            public Boolean getValue(DBSession dBSession) {
                return Boolean.valueOf(dBSession.getSelectedTermsOnly());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBSession dBSession, Boolean bool) {
                dBSession.setSelectedTermsOnly(bool.booleanValue());
            }
        };
        STUDYABLE = new PolymorphicRelationship<DBSession, StudyableModel>(modelType, Names.ITEM_ID, StudyableModelTypes.studyableModelClasses) { // from class: com.quizlet.db.data.models.persisted.fields.DBSessionFields.8
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "set";
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public StudyableModel getModel(DBSession dBSession) {
                return dBSession.getStudyableModel();
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public ModelType<? extends StudyableModel> getToModelType(Long l) {
                G1 g1A = G1.a(Integer.valueOf(l.intValue()));
                if (g1A != null) {
                    int i = AnonymousClass10.$SwitchMap$com$quizlet$generated$enums$StudyableType[g1A.ordinal()];
                    if (i == 1) {
                        return Models.STUDY_SET;
                    }
                    if (i == 2) {
                        return Models.FOLDER;
                    }
                }
                throw new IllegalArgumentException("Illegal polymorphicReferenceKey: " + l);
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBSession dBSession) {
                return Long.valueOf(dBSession.getItemId());
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public void setModel(DBSession dBSession, StudyableModel studyableModel) {
                dBSession.setStudyableModel(studyableModel);
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBSession dBSession, Long l) {
                dBSession.setItemId(l.longValue());
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public ModelType getToModelType(DBSession dBSession) {
                G1 g1A = G1.a(Integer.valueOf(dBSession.getItemType()));
                if (g1A != null) {
                    return StudyableModel.getModelClass(g1A);
                }
                Locale locale = Locale.US;
                c.a(new Throwable("DBSessionFields - Invalid toModelType(" + dBSession.getItemType() + ") for DBSession(" + dBSession.getId() + ")"));
                return null;
            }
        };
        PERSON = new NoModelRelationship<DBSession, DBUser>(modelType, "personId", Models.USER) { // from class: com.quizlet.db.data.models.persisted.fields.DBSessionFields.9
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "user";
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBSession dBSession) {
                return Long.valueOf(dBSession.getPersonId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBSession dBSession, Long l) {
                dBSession.setPersonId(l.longValue());
            }
        };
    }
}
