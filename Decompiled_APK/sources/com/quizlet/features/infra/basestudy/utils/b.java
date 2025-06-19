package com.quizlet.features.infra.basestudy.utils;

import assistantMode.enums.m;
import assistantMode.refactored.modelTypes.CardSide;
import assistantMode.types.h;
import assistantMode.types.k;
import assistantMode.types.test.TestSettings;
import com.quizlet.db.data.models.persisted.DBDiagramShape;
import com.quizlet.db.data.models.persisted.DBImage;
import com.quizlet.db.data.models.persisted.DBImageRef;
import com.quizlet.features.infra.studysetting.data.TestStudyModeConfig;
import com.quizlet.generated.enums.O1;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class b {
    public static final ArrayList a(m mVar, List list) {
        ArrayList arrayList = new ArrayList();
        for (Object obj : list) {
            if (((CardSide) obj).b == mVar) {
                arrayList.add(obj);
            }
        }
        ArrayList arrayList2 = new ArrayList(C.q(arrayList, 10));
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            arrayList2.add(Long.valueOf(((CardSide) it2.next()).a));
        }
        return arrayList2;
    }

    public static final k b(DBImage dBImage) {
        Intrinsics.checkNotNullParameter(dBImage, "<this>");
        long id = dBImage.getId();
        String mediumUrl = dBImage.getMediumUrl();
        if (mediumUrl == null) {
            mediumUrl = "";
        }
        String smallUrl = dBImage.getSmallUrl();
        if (smallUrl == null) {
            smallUrl = "";
        }
        String squareUrl = dBImage.getSquareUrl();
        if (squareUrl == null) {
            squareUrl = "";
        }
        String serverMediumUrl = dBImage.getServerMediumUrl();
        if (serverMediumUrl == null) {
            serverMediumUrl = "";
        }
        String serverSmallUrl = dBImage.getServerSmallUrl();
        if (serverSmallUrl == null) {
            serverSmallUrl = "";
        }
        String serverSquareUrl = dBImage.getServerSquareUrl();
        if (serverSquareUrl == null) {
            serverSquareUrl = "";
        }
        String code = dBImage.getCode();
        Intrinsics.checkNotNullExpressionValue(code, "getCode(...)");
        long jIntValue = dBImage.getHeight().intValue();
        long jIntValue2 = dBImage.getWidth().intValue();
        Long personId = dBImage.getPersonId();
        Intrinsics.checkNotNullExpressionValue(personId, "getPersonId(...)");
        long jLongValue = personId.longValue();
        Long timestamp = dBImage.getTimestamp();
        Intrinsics.checkNotNullExpressionValue(timestamp, "getTimestamp(...)");
        return new k(mediumUrl, smallUrl, squareUrl, serverMediumUrl, serverSmallUrl, serverSquareUrl, code, jIntValue, id, dBImage.getLastModified(), jLongValue, timestamp.longValue(), jIntValue2);
    }

    public static final ArrayList c(List list) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            DBImageRef dBImageRef = (DBImageRef) it2.next();
            Intrinsics.checkNotNullParameter(dBImageRef, "<this>");
            DBImage image = dBImageRef.getImage();
            Intrinsics.checkNotNullExpressionValue(image, "getImage(...)");
            arrayList.add(b(image));
        }
        return arrayList;
    }

    public static final ArrayList d(List list) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            DBDiagramShape dBDiagramShape = (DBDiagramShape) it2.next();
            Intrinsics.checkNotNullParameter(dBDiagramShape, "<this>");
            long setId = dBDiagramShape.getSetId();
            String shape = dBDiagramShape.getShape();
            Intrinsics.checkNotNullExpressionValue(shape, "getShape(...)");
            arrayList.add(new h(setId, dBDiagramShape.getTermId(), shape));
        }
        return arrayList;
    }

    public static final m e(O1 o1) {
        int i = a.a[o1.ordinal()];
        if (i == 1) {
            return m.b;
        }
        if (i == 2) {
            return m.c;
        }
        if (i == 3) {
            return m.d;
        }
        timber.log.c.a.o("Cannot map TermSide [" + o1 + "] to StudiableCardSideLabel", new Object[0]);
        return null;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x003d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.util.ArrayList f(java.util.List r22, java.util.List r23, java.util.List r24) {
        /*
            Method dump skipped, instructions count: 530
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.basestudy.utils.b.f(java.util.List, java.util.List, java.util.List):java.util.ArrayList");
    }

    public static final ArrayList g(List list) {
        ArrayList arrayListM = assistantMode.refactored.a.m("<this>", list);
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            m mVarE = e((O1) it2.next());
            if (mVarE != null) {
                arrayListM.add(mVarE);
            }
        }
        return arrayListM;
    }

    public static final TestSettings h(TestStudyModeConfig testStudyModeConfig) {
        assistantMode.enums.k kVar;
        Intrinsics.checkNotNullParameter(testStudyModeConfig, "<this>");
        HashSet<com.quizlet.sharedconfig.study_setting_metadata.b> hashSet = testStudyModeConfig.d;
        ArrayList arrayList = new ArrayList(C.q(hashSet, 10));
        for (com.quizlet.sharedconfig.study_setting_metadata.b bVar : hashSet) {
            Intrinsics.checkNotNullParameter(bVar, "<this>");
            switch (bVar) {
                case WRITTEN:
                    kVar = assistantMode.enums.k.b;
                    break;
                case MATCHING:
                    kVar = assistantMode.enums.k.c;
                    break;
                case MULTIPLE_CHOICE:
                    kVar = assistantMode.enums.k.d;
                    break;
                case TRUE_FALSE:
                    kVar = assistantMode.enums.k.e;
                    break;
                case REVEAL_SELF_ASSESSMENT:
                    kVar = assistantMode.enums.k.f;
                    break;
                case MULTIPLE_CHOICE_WITH_NONE_OPTION:
                    kVar = assistantMode.enums.k.g;
                    break;
                case COPY_ANSWER:
                    kVar = assistantMode.enums.k.h;
                    break;
                case FILL_IN_THE_BLANK:
                    kVar = assistantMode.enums.k.l;
                    break;
                default:
                    throw new NoWhenBranchMatchedException();
            }
            arrayList.add(kVar);
        }
        ArrayList arrayListG = g(testStudyModeConfig.b);
        ArrayList arrayListG2 = g(testStudyModeConfig.c);
        Boolean bool = Boolean.FALSE;
        return new TestSettings(arrayList, arrayListG, arrayListG2, testStudyModeConfig.a, bool, bool, bool, null, null, null, null, null);
    }
}
