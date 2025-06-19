package com.quizlet.features.infra.studysetting.datasource;

import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBAnswerFields;
import com.quizlet.db.data.models.persisted.fields.DBDiagramShapeFields;
import com.quizlet.db.data.models.persisted.fields.DBGroupFields;
import com.quizlet.db.data.models.persisted.fields.DBGroupMembershipFields;
import com.quizlet.db.data.models.persisted.fields.DBImageRefFields;
import com.quizlet.db.data.models.persisted.fields.DBStudySettingFields;
import com.quizlet.db.data.models.persisted.fields.DBTermFields;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.G1;
import com.quizlet.infra.legacysyncengine.datasources.o;
import com.quizlet.infra.legacysyncengine.net.c;
import com.quizlet.infra.legacysyncengine.orm.b;
import java.util.Set;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends o {
    public a(c loader, long j, long j2, A1 a1) {
        Intrinsics.checkNotNullParameter(loader, "loader");
        b bVar = new b(Models.ANSWER);
        bVar.b(Long.valueOf(j), DBAnswerFields.SET);
        bVar.b(Long.valueOf(j2), DBAnswerFields.PERSON);
        if (a1 != null) {
            bVar.b(Long.valueOf(a1.a()), DBAnswerFields.MODE_TYPE);
        }
        Unit unit = Unit.a;
        super(loader, bVar.a());
    }

    public a(c loader, Set setIds) {
        Intrinsics.checkNotNullParameter(loader, "loader");
        Intrinsics.checkNotNullParameter(setIds, "setIds");
        b bVar = new b(Models.TERM);
        Relationship<DBTerm, DBStudySet> relationship = DBTermFields.SET;
        bVar.c(relationship, setIds, null);
        bVar.e(relationship);
        super(loader, bVar.a());
    }

    public a(c loader, long j, long j2, G1 studyableType) {
        Intrinsics.checkNotNullParameter(loader, "loader");
        Intrinsics.checkNotNullParameter(studyableType, "studyableType");
        b bVar = new b(Models.STUDY_SETTING);
        bVar.b(Long.valueOf(j2), DBStudySettingFields.PERSON);
        bVar.d(DBStudySettingFields.STUDYABLE, Long.valueOf(j), Long.valueOf(studyableType.b()));
        bVar.b(Long.valueOf(studyableType.b()), DBStudySettingFields.STUDYABLE_TYPE);
        super(loader, bVar.a());
    }

    public a(c loader, long j, int i) {
        switch (i) {
            case 5:
                Intrinsics.checkNotNullParameter(loader, "loader");
                b bVar = new b(Models.DIAGRAM_SHAPE);
                bVar.b(Long.valueOf(j), DBDiagramShapeFields.SET_ID);
                super(loader, bVar.a());
                break;
            case 6:
            default:
                Intrinsics.checkNotNullParameter(loader, "loader");
                b bVar2 = new b(Models.GROUP_MEMBERSHIP);
                bVar2.b(Long.valueOf(j), DBGroupMembershipFields.USER);
                bVar2.e(DBGroupMembershipFields.CLASS, DBGroupFields.SCHOOL);
                super(loader, bVar2.a());
                break;
            case 7:
                Intrinsics.checkNotNullParameter(loader, "loader");
                b bVar3 = new b(Models.IMAGE_REF);
                bVar3.b(Long.valueOf(j), DBImageRefFields.MODEL_ID);
                bVar3.e(DBImageRefFields.IMAGE);
                super(loader, bVar3.a());
                break;
        }
    }
}
