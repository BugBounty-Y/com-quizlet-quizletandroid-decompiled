package com.quizlet.db.data.models.persisted.fields;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.quizlet.db.data.models.base.ColumnField;
import com.quizlet.db.data.models.base.ModelField;
import com.quizlet.db.data.models.interfaces.StudyableModel;
import com.quizlet.db.data.models.persisted.DBStudySetting;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.base.StudyableModelTypes;
import com.quizlet.db.data.orm.NoModelRelationship;
import com.quizlet.db.data.orm.PolymorphicRelationship;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.generated.enums.G1;
import java.util.Locale;
import timber.log.c;

/* loaded from: classes2.dex */
public class DBStudySettingFields {
    public static final ModelField<DBStudySetting, Long> LOCAL_ID;
    public static final Relationship<DBStudySetting, DBUser> PERSON;
    public static final ModelField<DBStudySetting, Long> SETTING_TYPE;
    public static final Relationship<DBStudySetting, StudyableModel> STUDYABLE;
    public static final ModelField<DBStudySetting, Long> STUDYABLE_TYPE;

    /* renamed from: com.quizlet.db.data.models.persisted.fields.DBStudySettingFields$6, reason: invalid class name */
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
        public static final String LOCAL_ID = "localGeneratedId";
        public static final String PERSON_ID = "personId";
        public static final String SETTING_TYPE = "setting_type";
        public static final String SETTING_VALUE = "setting_value";
        public static final String STUDYABLE_ID = "studyable_id";
        public static final String STUDYABLE_TYPE = "studyable_type";
    }

    static {
        ModelType<DBStudySetting> modelType = Models.STUDY_SETTING;
        LOCAL_ID = new ColumnField<DBStudySetting, Long>(modelType, "localGeneratedId") { // from class: com.quizlet.db.data.models.persisted.fields.DBStudySettingFields.1
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBStudySetting dBStudySetting) {
                return Long.valueOf(dBStudySetting.getLocalId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBStudySetting dBStudySetting, Long l) {
                dBStudySetting.setLocalId(l.longValue());
            }
        };
        STUDYABLE_TYPE = new ColumnField<DBStudySetting, Long>(modelType, Names.STUDYABLE_TYPE) { // from class: com.quizlet.db.data.models.persisted.fields.DBStudySettingFields.2
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBStudySetting dBStudySetting) {
                return Long.valueOf(dBStudySetting.getStudyableType());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBStudySetting dBStudySetting, Long l) {
                dBStudySetting.setStudyableType(l.intValue());
            }
        };
        SETTING_TYPE = new ColumnField<DBStudySetting, Long>(modelType, Names.SETTING_TYPE) { // from class: com.quizlet.db.data.models.persisted.fields.DBStudySettingFields.3
            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBStudySetting dBStudySetting) {
                return Long.valueOf(dBStudySetting.getSettingType());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBStudySetting dBStudySetting, Long l) {
                dBStudySetting.setSettingType(l.intValue());
            }
        };
        STUDYABLE = new PolymorphicRelationship<DBStudySetting, StudyableModel>(modelType, Names.STUDYABLE_ID, StudyableModelTypes.studyableModelClasses) { // from class: com.quizlet.db.data.models.persisted.fields.DBStudySettingFields.4
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "set";
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public StudyableModel getModel(DBStudySetting dBStudySetting) {
                return dBStudySetting.getStudyableModel();
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
            public Long getValue(DBStudySetting dBStudySetting) {
                return Long.valueOf(dBStudySetting.getStudyableId());
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public void setModel(DBStudySetting dBStudySetting, StudyableModel studyableModel) {
                dBStudySetting.setStudyableModel(studyableModel);
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBStudySetting dBStudySetting, Long l) {
                dBStudySetting.setStudyableId(l.longValue());
            }

            @Override // com.quizlet.db.data.orm.Relationship
            public ModelType<? extends StudyableModel> getToModelType(DBStudySetting dBStudySetting) {
                G1 g1A = G1.a(Integer.valueOf(dBStudySetting.getStudyableType()));
                if (g1A == null) {
                    Locale locale = Locale.US;
                    c.a(new Throwable(AbstractC0147y.c(dBStudySetting.getStudyableType(), "DBStudySettingFields - Invalid toModelType(", ")")));
                    return null;
                }
                return StudyableModel.getModelClass(g1A);
            }
        };
        PERSON = new NoModelRelationship<DBStudySetting, DBUser>(modelType, "personId", Models.USER) { // from class: com.quizlet.db.data.models.persisted.fields.DBStudySettingFields.5
            @Override // com.quizlet.db.data.orm.Relationship
            public String getApiAssociationName() {
                return "user";
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public Long getValue(DBStudySetting dBStudySetting) {
                return Long.valueOf(dBStudySetting.getPersonId());
            }

            @Override // com.quizlet.db.data.models.base.ModelField
            public void setValue(DBStudySetting dBStudySetting, Long l) {
                dBStudySetting.setPersonId(l.longValue());
            }
        };
    }
}
