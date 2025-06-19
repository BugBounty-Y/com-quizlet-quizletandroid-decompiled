package com.quizlet.infra.legacysyncengine.features.properties;

import com.quizlet.data.model.E;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.DBUser;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.functions.i;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements h, i {
    public static final c b = new c(0);
    public static final c c = new c(1);
    public static final c d = new c(2);
    public static final c e = new c(3);
    public static final c f = new c(4);
    public static final c g = new c(5);
    public static final c h = new c(6);
    public static final c i = new c(7);
    public static final c j = new c(8);
    public static final c k = new c(9);
    public static final c l = new c(10);
    public static final c m = new c(11);
    public static final c n = new c(12);
    public final /* synthetic */ int a;

    public /* synthetic */ c(int i2) {
        this.a = i2;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 0:
                DBStudySet it2 = (DBStudySet) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return Long.valueOf(it2.getCreatorId());
            case 1:
                DBStudySet it3 = (DBStudySet) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                return it3.getDefLang();
            case 2:
                List list = (List) obj;
                ArrayList arrayListM = assistantMode.refactored.a.m("terms", list);
                Iterator it4 = list.iterator();
                while (it4.hasNext()) {
                    String definition = ((DBTerm) it4.next()).getDefinition();
                    if (definition != null) {
                        arrayListM.add(definition);
                    }
                }
                return arrayListM;
            case 3:
                DBStudySet s = (DBStudySet) obj;
                Intrinsics.checkNotNullParameter(s, "s");
                DBUser creator = s.getCreator();
                boolean z = false;
                if (creator != null && creator.getUserUpgradeType() == 2) {
                    z = true;
                }
                return Boolean.valueOf(z);
            case 4:
                DBStudySet s2 = (DBStudySet) obj;
                Intrinsics.checkNotNullParameter(s2, "s");
                DBUser creator2 = s2.getCreator();
                boolean z2 = false;
                if (creator2 != null && creator2.getIsVerified()) {
                    z2 = true;
                }
                return Boolean.valueOf(z2);
            case 5:
                DBStudySet s3 = (DBStudySet) obj;
                Intrinsics.checkNotNullParameter(s3, "s");
                return Boolean.valueOf(s3.getPasswordUse());
            case 6:
                DBStudySet s4 = (DBStudySet) obj;
                Intrinsics.checkNotNullParameter(s4, "s");
                return Boolean.valueOf(s4.getAccessType() == 2);
            case 7:
            case 9:
            default:
                List list2 = (List) obj;
                ArrayList arrayListM2 = assistantMode.refactored.a.m("classMemberships", list2);
                for (Object obj2 : list2) {
                    if (((E) obj2).h) {
                        arrayListM2.add(obj2);
                    }
                }
                ArrayList arrayList = new ArrayList(C.q(arrayListM2, 10));
                Iterator it5 = arrayListM2.iterator();
                while (it5.hasNext()) {
                    arrayList.add(Long.valueOf(((E) it5.next()).b));
                }
                return arrayList;
            case 8:
                List l2 = (List) obj;
                Intrinsics.checkNotNullParameter(l2, "l");
                return (DBStudySet) CollectionsKt.L(l2);
            case 10:
                DBStudySet it6 = (DBStudySet) obj;
                Intrinsics.checkNotNullParameter(it6, "it");
                return it6.getWordLang();
            case 11:
                List list3 = (List) obj;
                ArrayList arrayListM3 = assistantMode.refactored.a.m("terms", list3);
                Iterator it7 = list3.iterator();
                while (it7.hasNext()) {
                    String word = ((DBTerm) it7.next()).getWord();
                    if (word != null) {
                        arrayListM3.add(word);
                    }
                }
                return arrayListM3;
        }
    }

    @Override // io.reactivex.rxjava3.functions.i
    public boolean test(Object obj) {
        switch (this.a) {
            case 7:
                List l2 = (List) obj;
                Intrinsics.checkNotNullParameter(l2, "l");
                return !l2.isEmpty();
            default:
                List l3 = (List) obj;
                Intrinsics.checkNotNullParameter(l3, "l");
                return !l3.isEmpty();
        }
    }
}
