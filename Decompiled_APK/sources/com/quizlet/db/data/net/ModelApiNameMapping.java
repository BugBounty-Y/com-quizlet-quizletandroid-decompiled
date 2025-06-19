package com.quizlet.db.data.net;

import androidx.appcompat.widget.C0122z;
import com.google.common.collect.C;
import com.quizlet.db.data.models.base.AssociationNames;
import com.quizlet.db.data.models.persisted.DBBookmark;
import com.quizlet.db.data.models.persisted.DBDiagramShape;
import com.quizlet.db.data.models.persisted.DBImageRef;
import com.quizlet.db.data.models.persisted.DBUserStudyable;
import com.quizlet.db.data.models.persisted.base.Models;

/* loaded from: classes2.dex */
public class ModelApiNameMapping {
    public static final C a;

    static {
        C0122z c0122z = new C0122z(4);
        c0122z.u(Models.ANSWER, "answer");
        c0122z.u(Models.BOOKMARK, DBBookmark.TABLE_NAME);
        c0122z.u(Models.GROUP, AssociationNames.CLASS);
        c0122z.u(Models.GROUP_MEMBERSHIP, AssociationNames.CLASS_MEMBERSHIP);
        c0122z.u(Models.GROUP_SET, "classSet");
        c0122z.u(Models.GROUP_FOLDER, "classFolder");
        c0122z.u(Models.PROGRESS_RESET, "progressReset");
        c0122z.u(Models.ENTERED_SET_PASSWORD, "enteredSetPassword");
        c0122z.u(Models.FOLDER, "folder");
        c0122z.u(Models.SCHOOL, "school");
        c0122z.u(Models.SELECTED_TERM, "selectedTerm");
        c0122z.u(Models.SESSION, "session");
        c0122z.u(Models.STUDY_SET, "set");
        c0122z.u(Models.STUDY_SETTING, "studySetting");
        c0122z.u(Models.TERM, "term");
        c0122z.u(Models.USER, "user");
        c0122z.u(Models.IMAGE, "image");
        c0122z.u(Models.USER_STUDYABLE, DBUserStudyable.TABLE_NAME);
        c0122z.u(Models.IMAGE_REF, DBImageRef.TABLE_NAME);
        c0122z.u(Models.DIAGRAM_SHAPE, DBDiagramShape.TABLE_NAME);
        c0122z.u(Models.QUESTION_ATTRIBUTE, "questionAttribute");
        c0122z.u(Models.OFFLINE_ENTITY, "offlineEntity");
        a = c0122z.h();
    }
}
