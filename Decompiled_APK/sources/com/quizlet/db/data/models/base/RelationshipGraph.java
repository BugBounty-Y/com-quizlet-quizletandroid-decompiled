package com.quizlet.db.data.models.base;

import androidx.collection.C0219q;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.fields.DBAnswerFields;
import com.quizlet.db.data.models.persisted.fields.DBBookmarkFields;
import com.quizlet.db.data.models.persisted.fields.DBDiagramShapeFields;
import com.quizlet.db.data.models.persisted.fields.DBEnteredSetPasswordFields;
import com.quizlet.db.data.models.persisted.fields.DBFolderFields;
import com.quizlet.db.data.models.persisted.fields.DBGroupFields;
import com.quizlet.db.data.models.persisted.fields.DBGroupMembershipFields;
import com.quizlet.db.data.models.persisted.fields.DBGroupSetFields;
import com.quizlet.db.data.models.persisted.fields.DBImageRefFields;
import com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields;
import com.quizlet.db.data.models.persisted.fields.DBQuestionAttributeFields;
import com.quizlet.db.data.models.persisted.fields.DBSelectedTermFields;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.quizlet.db.data.models.persisted.fields.DBStudySettingFields;
import com.quizlet.db.data.models.persisted.fields.DBTermFields;
import com.quizlet.db.data.models.persisted.fields.DBUserStudyableFields;
import com.quizlet.db.data.orm.Relationship;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* loaded from: classes2.dex */
public class RelationshipGraph {
    protected final List<Relationship> relationships;

    public RelationshipGraph() {
        ArrayList arrayList = new ArrayList();
        this.relationships = arrayList;
        arrayList.add(DBBookmarkFields.PERSON);
        arrayList.add(DBBookmarkFields.FOLDER);
        arrayList.add(DBFolderFields.PERSON);
        arrayList.add(DBGroupFields.SCHOOL);
        arrayList.add(DBGroupSetFields.GROUP);
        arrayList.add(DBGroupSetFields.SET);
        arrayList.add(DBGroupSetFields.CREATOR);
        arrayList.add(DBAnswerFields.TERM);
        arrayList.add(DBAnswerFields.SESSION);
        arrayList.add(DBAnswerFields.SET);
        arrayList.add(DBAnswerFields.PERSON);
        arrayList.add(DBSessionFields.STUDYABLE);
        arrayList.add(DBSessionFields.PERSON);
        arrayList.add(DBStudySettingFields.STUDYABLE);
        arrayList.add(DBStudySettingFields.PERSON);
        arrayList.add(DBGroupMembershipFields.CLASS);
        arrayList.add(DBGroupMembershipFields.USER);
        arrayList.add(DBStudySetFields.CREATOR);
        arrayList.add(DBSelectedTermFields.SET);
        arrayList.add(DBSelectedTermFields.TERM);
        arrayList.add(DBSelectedTermFields.PERSON);
        arrayList.add(DBTermFields.SET);
        arrayList.add(DBTermFields.DEFINITION_IMAGE);
        arrayList.add(DBEnteredSetPasswordFields.SET);
        arrayList.add(DBEnteredSetPasswordFields.PERSON);
        arrayList.add(DBUserStudyableFields.PERSON);
        arrayList.add(DBUserStudyableFields.SET);
        arrayList.add(DBDiagramShapeFields.SET_ID);
        arrayList.add(DBDiagramShapeFields.TERM_ID);
        arrayList.add(DBImageRefFields.IMAGE);
        arrayList.add(DBQuestionAttributeFields.ANSWER_ID);
        arrayList.add(DBQuestionAttributeFields.PERSON_ID);
        arrayList.add(DBQuestionAttributeFields.SET_ID);
        arrayList.add(DBQuestionAttributeFields.TERM_ID);
        arrayList.add(DBGroupFields.CREATOR);
        arrayList.add(DBOfflineEntityFields.STUDYABLE);
    }

    public <N extends DBModel> List<Relationship<? extends DBModel, N>> getToManyRelationships(ModelType<N> modelType) {
        ArrayList arrayList = new ArrayList();
        for (Relationship relationship : this.relationships) {
            Iterator it2 = relationship.getToModelTypes().iterator();
            while (it2.hasNext()) {
                if (((ModelType) it2.next()).equals(modelType)) {
                    arrayList.add(relationship);
                }
            }
        }
        return arrayList;
    }

    public <N extends DBModel> List<Relationship<N, ? extends DBModel>> getToOneRelationships(ModelType<N> modelType) {
        ArrayList arrayList = new ArrayList();
        for (Relationship relationship : this.relationships) {
            if (relationship.getFromModelType().equals(modelType)) {
                arrayList.add(relationship);
            }
        }
        return arrayList;
    }

    public final <T extends DBModel> void resolveRelations(Map<ModelType, C0219q> map, T t) {
        C0219q c0219q;
        for (Relationship relationship : getToOneRelationships(t.getModelType())) {
            ModelIdentity<T> toModelIdentity = relationship.getToModelIdentity(t);
            relationship.setModel(t, (toModelIdentity == null || (c0219q = map.get(toModelIdentity.getModelType())) == null) ? null : (DBModel) c0219q.c(toModelIdentity.getSingleFieldIdentityValue().longValue()));
        }
    }
}
