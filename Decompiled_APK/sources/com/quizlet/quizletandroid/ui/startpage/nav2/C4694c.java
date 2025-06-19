package com.quizlet.quizletandroid.ui.startpage.nav2;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.mlkit_vision_barcode.F6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3587b6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3760x4;
import com.quizlet.data.model.AbstractC4165s1;
import com.quizlet.data.model.S1;
import com.quizlet.data.model.User;
import com.quizlet.db.data.models.persisted.DBFolder;
import com.quizlet.db.data.models.persisted.DBGroup;
import com.quizlet.db.data.models.persisted.DBSchool;
import com.quizlet.db.data.models.persisted.DBStudySet;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4694c implements io.reactivex.rxjava3.functions.h, io.reactivex.rxjava3.functions.b {
    public static final C4694c b = new C4694c(0);
    public static final C4694c c = new C4694c(1);
    public static final C4694c d = new C4694c(2);
    public static final C4694c e = new C4694c(3);
    public static final C4694c f = new C4694c(4);
    public static final C4694c g = new C4694c(5);
    public static final C4694c h = new C4694c(6);
    public final /* synthetic */ int a;

    public /* synthetic */ C4694c(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        String schoolString;
        String strD;
        switch (this.a) {
            case 0:
                AbstractC4165s1 recommendedSets = (AbstractC4165s1) obj;
                Intrinsics.checkNotNullParameter(recommendedSets, "recommendedSets");
                return AbstractC3587b6.f(recommendedSets);
            case 1:
                List classesList = (List) obj;
                Intrinsics.checkNotNullParameter(classesList, "classesList");
                List<DBGroup> listB = AbstractC3760x4.b(classesList, false);
                ArrayList arrayList = new ArrayList(kotlin.collections.C.q(listB, 10));
                for (DBGroup dBGroup : listB) {
                    Intrinsics.checkNotNullParameter(dBGroup, "<this>");
                    long id = dBGroup.getId();
                    String title = dBGroup.getTitle();
                    Intrinsics.checkNotNullExpressionValue(title, "getTitle(...)");
                    int numSets = dBGroup.getNumSets();
                    int numMembers = dBGroup.getNumMembers();
                    DBSchool school = dBGroup.getSchool();
                    String str = "";
                    if (school == null || (schoolString = school.getSchoolString()) == null) {
                        schoolString = "";
                    }
                    DBSchool school2 = dBGroup.getSchool();
                    if (school2 != null) {
                        Intrinsics.checkNotNullParameter(school2, "<this>");
                        String city = school2.getCity();
                        if (city == null || city.length() == 0) {
                            strD = "";
                        } else {
                            strD = AbstractC0147y.d("", school2.getCity());
                            String state = school2.getState();
                            if (state != null && state.length() != 0) {
                                strD = android.support.v4.media.session.a.l(strD, ", ", school2.getState());
                            }
                        }
                        if (strD != null) {
                            str = strD;
                        }
                    }
                    arrayList.add(new com.quizlet.ui.models.content.carditem.a(id, title, numSets, numMembers, schoolString, str));
                }
                return arrayList;
            case 2:
                List folders = (List) obj;
                Intrinsics.checkNotNullParameter(folders, "folders");
                ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(folders, 10));
                Iterator it2 = folders.iterator();
                while (it2.hasNext()) {
                    arrayList2.add(F6.b((DBFolder) it2.next()));
                }
                return arrayList2;
            case 3:
                List recommendedSets2 = (List) obj;
                Intrinsics.checkNotNullParameter(recommendedSets2, "recommendedSets");
                Intrinsics.checkNotNullParameter(recommendedSets2, "<this>");
                ArrayList arrayList3 = new ArrayList(kotlin.collections.C.q(recommendedSets2, 10));
                Iterator it3 = recommendedSets2.iterator();
                while (it3.hasNext()) {
                    arrayList3.add(AbstractC3587b6.f((AbstractC4165s1) it3.next()));
                }
                return arrayList3;
            case 4:
                Throwable it4 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                return it4 instanceof UnknownHostException ? io.reactivex.rxjava3.core.i.p(kotlin.collections.K.a) : io.reactivex.rxjava3.core.i.k(it4);
            case 5:
            default:
                List list = (List) obj;
                ArrayList arrayListM = assistantMode.refactored.a.m("sets", list);
                for (Object obj2 : list) {
                    if (!((S1) obj2).a.m) {
                        arrayListM.add(obj2);
                    }
                }
                HashSet hashSet = new HashSet();
                ArrayList arrayList4 = new ArrayList();
                Iterator it5 = arrayListM.iterator();
                while (it5.hasNext()) {
                    Object next = it5.next();
                    if (hashSet.add(Long.valueOf(((S1) next).a.a))) {
                        arrayList4.add(next);
                    }
                }
                ArrayList arrayList5 = new ArrayList(kotlin.collections.C.q(arrayList4, 10));
                Iterator it6 = arrayList4.iterator();
                while (it6.hasNext()) {
                    S1 s1 = (S1) it6.next();
                    DBStudySet dBStudySet = new DBStudySet();
                    dBStudySet.setId(s1.a.a);
                    com.quizlet.data.model.I i = s1.a;
                    dBStudySet.setTitle(i.b);
                    dBStudySet.setNumTerms(i.c);
                    dBStudySet.setHasImages(Boolean.valueOf(i.d));
                    dBStudySet.setHasDiagrams(i.e);
                    dBStudySet.setAccessCodePrefix(i.j);
                    dBStudySet.setPasswordUse(i.k);
                    dBStudySet.setAccessType(i.l);
                    dBStudySet.setDeleted(i.m);
                    dBStudySet.setPublishedTimestamp(Long.valueOf(i.n));
                    dBStudySet.setTimestamp((int) i.o);
                    User user = s1.b;
                    dBStudySet.setCreator(assistantMode.utils.studiableMetadata.b.P(user));
                    dBStudySet.setThumbnailUrl(i.p);
                    dBStudySet.setCreatorId(user.a);
                    arrayList5.add(dBStudySet);
                }
                return arrayList5;
            case 6:
                Boolean isUnderAge = (Boolean) obj;
                Intrinsics.checkNotNullParameter(isUnderAge, "isUnderAge");
                return isUnderAge.booleanValue() ? kotlin.collections.A.b(com.quizlet.quizletandroid.ui.startpage.nav2.model.I.d) : kotlin.collections.K.a;
        }
    }

    public C4694c(C3 c3) {
        this.a = 7;
    }

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object obj, Object obj2) {
        List p0 = (List) obj;
        Boolean p1 = (Boolean) obj2;
        Intrinsics.checkNotNullParameter(p0, "p0");
        Intrinsics.checkNotNullParameter(p1, "p1");
        return new Pair(p0, p1);
    }
}
