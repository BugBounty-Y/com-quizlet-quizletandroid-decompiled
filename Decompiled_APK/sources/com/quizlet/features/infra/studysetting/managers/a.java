package com.quizlet.features.infra.studysetting.managers;

import androidx.collection.Y;
import assistantMode.enums.k;
import assistantMode.enums.w;
import assistantMode.enums.y;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_barcode.L6;
import com.google.android.gms.internal.mlkit_vision_barcode.M6;
import com.quizlet.db.data.models.interfaces.StudyableModel;
import com.quizlet.db.data.models.persisted.DBStudySetting;
import com.quizlet.db.data.models.persisted.fields.DBUserStudyableFields;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import com.quizlet.features.infra.studysetting.data.TestStudyModeConfig;
import com.quizlet.generated.enums.C1;
import com.quizlet.generated.enums.E1;
import com.quizlet.generated.enums.G1;
import com.quizlet.infra.legacysyncengine.net.f;
import com.quizlet.sharedconfig.study_setting_metadata.b;
import com.quizlet.sharedconfig.study_setting_metadata.c;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.C;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public static final Set h;
    public final f a;
    public final long b;
    public long c;
    public G1 d;
    public boolean e;
    public LinkedHashMap f;
    public boolean g;

    static {
        Intrinsics.checkNotNullExpressionValue(a.class.getSimpleName(), "getSimpleName(...)");
        b[] elements = {b.WRITTEN, b.MULTIPLE_CHOICE, b.REVEAL_SELF_ASSESSMENT, b.MULTIPLE_CHOICE_WITH_NONE_OPTION, b.COPY_ANSWER, b.FILL_IN_THE_BLANK};
        Intrinsics.checkNotNullParameter(elements, "elements");
        h = C4933y.T(elements);
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public a(f syncDispatcher, List initialSettings, long j, StudyableModel studyableModel, C1 defaultStudyPath) {
        this(syncDispatcher, j);
        Intrinsics.checkNotNullParameter(syncDispatcher, "syncDispatcher");
        Intrinsics.checkNotNullParameter(initialSettings, "initialSettings");
        Intrinsics.checkNotNullParameter(studyableModel, "studyableModel");
        Intrinsics.checkNotNullParameter(defaultStudyPath, "defaultStudyPath");
        studyableModel.getLocalId();
        Long studyableId = studyableModel.getStudyableId();
        Intrinsics.checkNotNullExpressionValue(studyableId, "getStudyableId(...)");
        long jLongValue = studyableId.longValue();
        G1 studyableType = studyableModel.getStudyableType();
        Intrinsics.checkNotNullExpressionValue(studyableType, "getStudyableType(...)");
        j(jLongValue, studyableType, initialSettings, defaultStudyPath);
    }

    public static boolean d(a aVar, E1 e1) {
        return aVar.e(e1, null) > 0;
    }

    public final void a() {
        if (!this.e) {
            throw new IllegalStateException("StudySettingManager parameters have not been initialized!");
        }
    }

    public final void b(E1 e1) {
        a();
        LinkedHashMap linkedHashMap = this.f;
        if (linkedHashMap == null) {
            Intrinsics.m("studySettings");
            throw null;
        }
        DBStudySetting dBStudySetting = (DBStudySetting) linkedHashMap.get(e1);
        if (dBStudySetting != null) {
            dBStudySetting.setDeleted(true);
        }
        if (dBStudySetting != null) {
            this.a.a(dBStudySetting);
        }
    }

    public final QuestionSettings c() {
        Set set;
        a();
        HashSet hashSetA = b.a((int) e(E1.ASSISTANT_MODE_QUESTION_TYPES, null));
        Intrinsics.checkNotNullExpressionValue(hashSetA, "setFromBitmask(...)");
        ArrayList arrayList = new ArrayList();
        Iterator it2 = hashSetA.iterator();
        while (true) {
            boolean zHasNext = it2.hasNext();
            set = h;
            if (!zHasNext) {
                break;
            }
            Object next = it2.next();
            if (set.contains((b) next)) {
                arrayList.add(next);
            }
        }
        boolean zIsEmpty = arrayList.isEmpty();
        Collection collection = arrayList;
        if (zIsEmpty) {
            collection = set;
        }
        Set setA0 = CollectionsKt.A0(collection);
        return new QuestionSettings(M6.d(e(E1.PROMPT_TERM_SIDES, null)), M6.d(e(E1.ANSWER_TERM_SIDES, null)), d(this, E1.TAP_TO_PLAY_AUDIO), setA0.contains(b.REVEAL_SELF_ASSESSMENT), setA0.contains(b.MULTIPLE_CHOICE), setA0.contains(b.WRITTEN), setA0.contains(b.FILL_IN_THE_BLANK), d(this, E1.ASSISTANT_MODE_WRITTEN_WORD_SIDE), d(this, E1.ASSISTANT_MODE_WRITTEN_DEFINITION_SIDE), null, null, f(), g(), d(this, E1.FLEXIBLE_GRADING_ACCEPT_PARTIAL_ANSWERS), e(E1.SMART_GRADING, 1L) > 0, d(this, E1.FLEXIBLE_GRADING_ACCEPT_ANSWERS_WITH_TYPOS), d(this, E1.SHUFFLE), d(this, E1.ASSISTANT_COPY_CORRECT_ANSWER_ENABLED));
    }

    /* JADX WARN: Type inference failed for: r4v1, types: [java.lang.Object, java.util.Map] */
    public final long e(E1 e1, Long l) {
        a();
        LinkedHashMap linkedHashMap = this.f;
        if (linkedHashMap == null) {
            Intrinsics.m("studySettings");
            throw null;
        }
        DBStudySetting dBStudySetting = (DBStudySetting) linkedHashMap.get(e1);
        if (dBStudySetting != null) {
            return dBStudySetting.getSettingValue();
        }
        if (l != null) {
            return l.longValue();
        }
        Long l2 = (Long) c.a.get(e1);
        if (l2 != null) {
            return l2.longValue();
        }
        throw new IllegalStateException("No existing or default setting found for " + e1);
    }

    public final com.quizlet.studiablemodels.assistantMode.a f() {
        Object next;
        kotlin.enums.b bVar = w.g;
        bVar.getClass();
        Y y = new Y(bVar, 5);
        while (true) {
            if (!y.hasNext()) {
                next = null;
                break;
            }
            next = y.next();
            w wVar = (w) next;
            if (!this.g) {
                Long lH = h(E1.STUDY_PATH_GOAL);
                if (lH != null && wVar.a == ((int) lH.longValue())) {
                    break;
                }
            } else if (wVar.a == ((int) e(E1.STUDY_PATH_GOAL, null))) {
                break;
            }
        }
        w wVar2 = (w) next;
        if (wVar2 == null) {
            return null;
        }
        Intrinsics.checkNotNullParameter(wVar2, "<this>");
        int iOrdinal = wVar2.ordinal();
        if (iOrdinal == 0) {
            return com.quizlet.studiablemodels.assistantMode.a.b;
        }
        if (iOrdinal == 1) {
            return com.quizlet.studiablemodels.assistantMode.a.a;
        }
        if (iOrdinal == 2) {
            return com.quizlet.studiablemodels.assistantMode.a.b;
        }
        if (iOrdinal == 3) {
            return com.quizlet.studiablemodels.assistantMode.a.c;
        }
        throw new NoWhenBranchMatchedException();
    }

    public final y g() {
        Object obj;
        Object next;
        kotlin.enums.b bVar = y.f;
        bVar.getClass();
        Y y = new Y(bVar, 5);
        while (true) {
            obj = null;
            if (!y.hasNext()) {
                break;
            }
            next = y.next();
            y yVar = (y) next;
            if (!this.g) {
                Long lH = h(E1.STUDY_PATH_KNOWLEDGE_LEVEL);
                if (lH != null && yVar.a == ((int) lH.longValue())) {
                    break;
                }
            } else if (yVar.a == ((int) e(E1.STUDY_PATH_KNOWLEDGE_LEVEL, null))) {
                break;
            }
        }
        obj = next;
        return (y) obj;
    }

    public final Long h(E1 e1) {
        a();
        LinkedHashMap linkedHashMap = this.f;
        if (linkedHashMap == null) {
            Intrinsics.m("studySettings");
            throw null;
        }
        DBStudySetting dBStudySetting = (DBStudySetting) linkedHashMap.get(e1);
        if (dBStudySetting == null || !dBStudySetting.getDeleted()) {
            LinkedHashMap linkedHashMap2 = this.f;
            if (linkedHashMap2 == null) {
                Intrinsics.m("studySettings");
                throw null;
            }
            DBStudySetting dBStudySetting2 = (DBStudySetting) linkedHashMap2.get(e1);
            if (dBStudySetting2 != null) {
                return Long.valueOf(dBStudySetting2.getSettingValue());
            }
        }
        return null;
    }

    public final TestStudyModeConfig i() {
        a();
        QuestionSettings questionSettingsC = c();
        int iE = (int) e(E1.TEST_QUESTION_COUNT, null);
        HashSet hashSetA = b.a((int) e(E1.TEST_QUESTION_TYPES, null));
        Intrinsics.checkNotNullExpressionValue(hashSetA, "setFromBitmask(...)");
        return new TestStudyModeConfig(iE, questionSettingsC.a, questionSettingsC.b, hashSetA, d(this, E1.INSTANT_FEEDBACK), false, questionSettingsC.n, questionSettingsC.o);
    }

    /* JADX WARN: Code restructure failed: missing block: B:51:0x0146, code lost:
    
        r11.put(r4, r10);
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void j(long r9, com.quizlet.generated.enums.G1 r11, java.util.List r12, com.quizlet.generated.enums.C1 r13) {
        /*
            Method dump skipped, instructions count: 350
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.studysetting.managers.a.j(long, com.quizlet.generated.enums.G1, java.util.List, com.quizlet.generated.enums.C1):void");
    }

    public final boolean k(E1 settingType) {
        Intrinsics.checkNotNullParameter(settingType, "settingType");
        a();
        LinkedHashMap linkedHashMap = this.f;
        if (linkedHashMap != null) {
            DBStudySetting dBStudySetting = (DBStudySetting) linkedHashMap.get(settingType);
            return (dBStudySetting != null ? Long.valueOf(dBStudySetting.getSettingValue()) : null) != null;
        }
        Intrinsics.m("studySettings");
        throw null;
    }

    public final void l(QuestionSettings settings) {
        Intrinsics.checkNotNullParameter(settings, "settings");
        a();
        List value = settings.a;
        Intrinsics.checkNotNullParameter(value, "value");
        n(E1.PROMPT_TERM_SIDES, M6.a(value));
        List value2 = settings.b;
        Intrinsics.checkNotNullParameter(value2, "value");
        n(E1.ANSWER_TERM_SIDES, M6.a(value2));
        m(E1.TAP_TO_PLAY_AUDIO, settings.c);
        ArrayList arrayList = settings.s;
        Intrinsics.checkNotNullParameter(arrayList, "<this>");
        ArrayList arrayList2 = new ArrayList(C.q(arrayList, 10));
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            arrayList2.add(L6.c((k) it2.next()));
        }
        Set questionTypes = CollectionsKt.A0(arrayList2);
        Intrinsics.checkNotNullParameter(questionTypes, "questionTypes");
        Iterator it3 = questionTypes.iterator();
        int i = 0;
        while (it3.hasNext()) {
            i |= ((b) it3.next()).a;
        }
        n(E1.ASSISTANT_MODE_QUESTION_TYPES, i);
        m(E1.ASSISTANT_MODE_WRITTEN_WORD_SIDE, settings.h);
        m(E1.ASSISTANT_MODE_WRITTEN_DEFINITION_SIDE, settings.i);
        m(E1.FLEXIBLE_GRADING_ACCEPT_PARTIAL_ANSWERS, settings.n);
        m(E1.SMART_GRADING, settings.o);
        m(E1.FLEXIBLE_GRADING_ACCEPT_ANSWERS_WITH_TYPOS, settings.p);
        m(E1.SHUFFLE, settings.q);
        m(E1.ASSISTANT_COPY_CORRECT_ANSWER_ENABLED, settings.r);
    }

    public final void m(E1 e1, boolean z) {
        n(e1, z ? 1L : 0L);
    }

    public final void n(E1 e1, long j) {
        a();
        LinkedHashMap linkedHashMap = this.f;
        if (linkedHashMap == null) {
            Intrinsics.m("studySettings");
            throw null;
        }
        Object obj = linkedHashMap.get(e1);
        if (obj == null) {
            Long lValueOf = Long.valueOf(this.c);
            G1 g1 = this.d;
            if (g1 == null) {
                Intrinsics.m(DBUserStudyableFields.Names.STUDYABLE_TYPE);
                throw null;
            }
            DBStudySetting dBStudySetting = new DBStudySetting(lValueOf, g1, Long.valueOf(this.b), e1, Long.valueOf(j));
            linkedHashMap.put(e1, dBStudySetting);
            obj = dBStudySetting;
        }
        DBStudySetting dBStudySetting2 = (DBStudySetting) obj;
        dBStudySetting2.setSettingValue(j);
        this.a.a(dBStudySetting2);
    }

    public final void o(com.quizlet.studiablemodels.assistantMode.a aVar) {
        if (aVar != null) {
            n(E1.STUDY_PATH_GOAL, K6.c(aVar).a);
        } else {
            b(E1.STUDY_PATH_GOAL);
        }
    }

    public final void p(y yVar) {
        if (yVar != null) {
            n(E1.STUDY_PATH_KNOWLEDGE_LEVEL, yVar.a);
        } else {
            b(E1.STUDY_PATH_KNOWLEDGE_LEVEL);
        }
    }

    public a(f syncDispatcher, long j) {
        Intrinsics.checkNotNullParameter(syncDispatcher, "syncDispatcher");
        this.g = true;
        this.a = syncDispatcher;
        this.b = j;
    }
}
