package com.quizlet.db.data.models.interfaces;

import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.interfaces.StudyableModel;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.generated.enums.G1;
import timber.log.c;

/* loaded from: classes2.dex */
public interface StudyableModel<M extends StudyableModel> extends DBModel {

    /* renamed from: com.quizlet.db.data.models.interfaces.StudyableModel$1, reason: invalid class name */
    public static /* synthetic */ class AnonymousClass1 {
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

    static ModelType getModelClass(G1 g1) {
        int i = AnonymousClass1.$SwitchMap$com$quizlet$generated$enums$StudyableType[g1.ordinal()];
        if (i == 1) {
            return Models.STUDY_SET;
        }
        if (i == 2) {
            return Models.FOLDER;
        }
        c.a.d("Class not defined for enum StudyableModel.TYPE value: %d", Integer.valueOf(g1.b()));
        return null;
    }

    @Deprecated
    String getDefLang();

    Long getStudyableId();

    G1 getStudyableType();

    String getTitle();

    @Deprecated
    String getWordLang();
}
