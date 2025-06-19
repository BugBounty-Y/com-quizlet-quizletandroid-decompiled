package com.quizlet.db.data.models.persisted.fields;

import com.quizlet.db.data.models.base.ColumnField;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.interfaces.StudyableModel;
import com.quizlet.db.data.models.persisted.DBOfflineEntity;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.base.StudyableModelTypes;
import com.quizlet.db.data.orm.PolymorphicRelationship;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.generated.enums.G1;
import java.util.Locale;
import timber.log.c;

/* loaded from: classes2.dex */
public class DBOfflineEntityFields {
    public static final ModelField<DBOfflineEntity, Long> LOCAL_ID;
    public static final ModelField<DBOfflineEntity, Long> MODEL_ID;
    public static final ModelField<DBOfflineEntity, Long> MODEL_TYPE;
    public static final ModelField<DBOfflineEntity, Long> OFFLINE_STATUS;
    public static final Relationship<DBOfflineEntity, StudyableModel> STUDYABLE;

    /* renamed from: com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields$6, reason: invalid class name */
    public static /* synthetic */ class AnonymousClass6 {
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
        public static final String ID = "id";
        public static final String LOCAL_ID = "localGeneratedId";
        public static final String MODEL_ID = "model_id";
        public static final String MODEL_TYPE = "model_type";
        public static final String OFFLINE_STATUS = "offline_status";
    }

    static {
        ModelType<DBOfflineEntity> modelType = Models.OFFLINE_ENTITY;
        LOCAL_ID = new ColumnField<DBOfflineEntity, Long>(modelType, "localGeneratedId") { // from class: com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields.1
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBOfflineEntity dBOfflineEntity) {
                return Long.valueOf(dBOfflineEntity.getLocalId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBOfflineEntity dBOfflineEntity, Long l) {
                dBOfflineEntity.setLocalId(l.longValue());
            }
        };
        OFFLINE_STATUS = new ColumnField<DBOfflineEntity, Long>(modelType, Names.OFFLINE_STATUS) { // from class: com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields.2
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBOfflineEntity dBOfflineEntity) {
                return Long.valueOf(dBOfflineEntity.getOfflineStatus());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBOfflineEntity dBOfflineEntity, Long l) {
                dBOfflineEntity.setOfflineStatus(l.intValue());
            }
        };
        String str = Names.MODEL_ID;
        MODEL_ID = new ColumnField<DBOfflineEntity, Long>(modelType, str) { // from class: com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields.3
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBOfflineEntity dBOfflineEntity) {
                return Long.valueOf(dBOfflineEntity.getSavedModelId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBOfflineEntity dBOfflineEntity, Long l) {
                dBOfflineEntity.setSavedModelId(l.longValue());
            }
        };
        MODEL_TYPE = new ColumnField<DBOfflineEntity, Long>(modelType, Names.MODEL_TYPE) { // from class: com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields.4
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBOfflineEntity dBOfflineEntity) {
                return Long.valueOf(dBOfflineEntity.getSavedModelType());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBOfflineEntity dBOfflineEntity, Long l) {
                dBOfflineEntity.setSavedModelType(l.intValue());
            }
        };
        STUDYABLE = new PolymorphicRelationship<DBOfflineEntity, StudyableModel>(modelType, str, StudyableModelTypes.studyableModelClasses) { // from class: com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields.5
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return null;
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public StudyableModel getModel(DBOfflineEntity dBOfflineEntity) {
                return dBOfflineEntity.getStudyableModel();
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public ModelType<? extends StudyableModel> getToModelType(Long l) {
                G1 g1A = G1.a(Integer.valueOf(l.intValue()));
                if (g1A != null) {
                    int i = AnonymousClass6.$SwitchMap$com$quizlet$generated$enums$StudyableType[g1A.ordinal()];
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
            public Long getValue(DBOfflineEntity dBOfflineEntity) {
                return Long.valueOf(dBOfflineEntity.getSavedModelId());
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public void setModel(DBOfflineEntity dBOfflineEntity, StudyableModel studyableModel) {
                dBOfflineEntity.setStudyableModel(studyableModel);
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBOfflineEntity dBOfflineEntity, Long l) {
                dBOfflineEntity.setSavedModelId(l.longValue());
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public ModelType getToModelType(DBOfflineEntity dBOfflineEntity) {
                G1 g1A = G1.a(Integer.valueOf(dBOfflineEntity.getSavedModelType()));
                if (g1A != null) {
                    return StudyableModel.getModelClass(g1A);
                }
                Locale locale = Locale.US;
                c.a(new Throwable("DBOfflineEntityFields - Invalid toModelType(" + dBOfflineEntity.getSavedModelType() + ") for DBOfflineEntity(" + dBOfflineEntity.getLocalId() + ")"));
                return null;
            }
        };
    }
}
