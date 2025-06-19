package com.quizlet.local.ormlite.models.bookmark;

import androidx.compose.foundation.text.z0;
import androidx.work.impl.model.l;
import androidx.work.impl.model.v;
import assistantMode.utils.studiableMetadata.b;
import com.google.android.datatransport.cct.internal.s;
import com.google.android.gms.internal.mlkit_vision_document_scanner.A;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3770y6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z;
import com.google.android.material.floatingactionbutton.c;
import com.j256.ormlite.dao.Dao;
import com.onetrust.otpublishers.headless.Internal.Helper.h;
import com.onetrust.otpublishers.headless.UI.fragment.q;
import com.quizlet.data.interactor.achievements.f;
import com.quizlet.data.model.AbstractC4119d0;
import com.quizlet.data.model.C4132h0;
import com.quizlet.data.model.C4181y;
import com.quizlet.data.model.D;
import com.quizlet.data.model.F;
import com.quizlet.data.model.StudySet;
import com.quizlet.data.model.User;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.models.persisted.DBBookmark;
import com.quizlet.db.data.models.persisted.DBGroupFolder;
import com.quizlet.db.data.models.persisted.DBGroupSet;
import com.quizlet.local.datastore.preferences.C4566c0;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.operators.maybe.w;
import io.reactivex.rxjava3.internal.operators.single.g;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.x;
import kotlin.u;

/* loaded from: classes3.dex */
public final class a implements com.quizlet.data.repository.base.a {
    public final /* synthetic */ int a = 6;
    public final Object b;
    public final Object c;
    public final Object d;

    public a(s database, ModelIdentityProvider modelIdentityProvider, b mapper) {
        Intrinsics.checkNotNullParameter(database, "database");
        Intrinsics.checkNotNullParameter(modelIdentityProvider, "modelIdentityProvider");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        this.b = modelIdentityProvider;
        this.c = mapper;
        this.d = (com.quizlet.local.ormlite.database.dao.b) database.i;
    }

    @Override // com.quizlet.data.repository.base.a
    public final p a(List models) {
        Object objC;
        Object objC2;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(models, "models");
                ArrayList arrayList = new ArrayList(C.q(models, 10));
                Iterator it2 = models.iterator();
                while (it2.hasNext()) {
                    C4181y data = (C4181y) it2.next();
                    Intrinsics.checkNotNullParameter(data, "data");
                    DBBookmark dBBookmark = new DBBookmark();
                    dBBookmark.setLocalId(data.a);
                    dBBookmark.setPersonId(data.b);
                    dBBookmark.setFolderId(data.c);
                    dBBookmark.setDeleted(data.d);
                    dBBookmark.setLastModified(data.e);
                    arrayList.add(dBBookmark);
                }
                g gVarE = ((ModelIdentityProvider) this.b).generateLocalIdsIfNeededAsync(arrayList).e(new c(this, 27));
                Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
                return gVarE;
            case 1:
                Intrinsics.checkNotNullParameter(models, "models");
                return f(models, false);
            case 2:
                Intrinsics.checkNotNullParameter(models, "models");
                ArrayList arrayList2 = new ArrayList(C.q(models, 10));
                Iterator it3 = models.iterator();
                while (it3.hasNext()) {
                    F data2 = (F) it3.next();
                    Intrinsics.checkNotNullParameter(data2, "data");
                    DBGroupSet dBGroupSet = new DBGroupSet();
                    Long l = data2.a;
                    if (l != null) {
                        dBGroupSet.setLocalId(l.longValue());
                    }
                    dBGroupSet.setClassId(data2.b);
                    dBGroupSet.setSetId(data2.c);
                    dBGroupSet.setUserId(data2.d);
                    dBGroupSet.setFolderId(data2.e);
                    dBGroupSet.setCanEdit(data2.f);
                    dBGroupSet.setTimestamp(data2.g);
                    Boolean bool = data2.h;
                    if (bool != null) {
                        dBGroupSet.setDeleted(bool.booleanValue());
                    }
                    Long l2 = data2.i;
                    if (l2 != null) {
                        dBGroupSet.setClientTimestamp(l2.longValue());
                    }
                    dBGroupSet.setLastModified(data2.j);
                    dBGroupSet.setDirty(data2.k);
                    arrayList2.add(dBGroupSet);
                }
                ArrayList classSetIds = new ArrayList(C.q(arrayList2, 10));
                Iterator it4 = arrayList2.iterator();
                while (it4.hasNext()) {
                    DBGroupSet dBGroupSet2 = (DBGroupSet) it4.next();
                    classSetIds.add(new com.quizlet.data.repository.classset.a(dBGroupSet2.getClassId(), dBGroupSet2.getSetId()));
                }
                com.quizlet.data.interactor.course.a aVar = (com.quizlet.data.interactor.course.a) this.d;
                aVar.getClass();
                Intrinsics.checkNotNullParameter(classSetIds, "ids");
                Dao daoD = aVar.d();
                Intrinsics.checkNotNullParameter(classSetIds, "classSetIds");
                String strS = classSetIds.isEmpty() ? "0" : CollectionsKt.S(classSetIds, "OR", "(", ")", new C4566c0(9), 24);
                g gVarG = com.quizlet.local.ormlite.util.b.b(daoD, x.c("\n                SELECT * FROM group_set\n                WHERE " + strS + "\n                AND " + A.a(false) + "\n            ")).g(new f(this, 20));
                Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
                g gVarE2 = gVarG.g(new com.quizlet.data.repository.explanations.myexplanations.a(arrayList2, false, this, 22)).e(new com.google.firebase.crashlytics.internal.settings.b((ModelIdentityProvider) this.b, 26));
                Intrinsics.checkNotNullExpressionValue(gVarE2, "flatMap(...)");
                g gVarE3 = gVarE2.e(new q(this, 22));
                Intrinsics.checkNotNullExpressionValue(gVarE3, "flatMap(...)");
                return gVarE3;
            case 3:
                ArrayList arrayListM = assistantMode.refactored.a.m("models", models);
                for (Object obj : models) {
                    if (((AbstractC4119d0) obj).c() != 0) {
                        arrayListM.add(obj);
                    }
                }
                ArrayList models2 = new ArrayList(C.q(arrayListM, 10));
                Iterator it5 = arrayListM.iterator();
                while (it5.hasNext()) {
                    models2.add(com.quizlet.local.ormlite.models.folder.a.a((AbstractC4119d0) it5.next()));
                }
                c cVar = (c) this.d;
                Intrinsics.checkNotNullParameter(models2, "models");
                if (models2.isEmpty()) {
                    objC = io.reactivex.rxjava3.internal.operators.completable.f.a;
                    Intrinsics.checkNotNullExpressionValue(objC, "complete(...)");
                } else {
                    Dao daoH = cVar.h();
                    Intrinsics.checkNotNullParameter(models2, "models");
                    objC = com.quizlet.local.ormlite.util.b.c(daoH, CollectionsKt.S(models2, null, null, null, new C4566c0(7), 31));
                }
                ArrayList arrayList3 = new ArrayList(C.q(models, 10));
                Iterator it6 = models.iterator();
                while (it6.hasNext()) {
                    arrayList3.add(Long.valueOf(((AbstractC4119d0) it6.next()).a()));
                }
                g gVarG2 = cVar.k(arrayList3).g(com.quizlet.local.ormlite.models.folder.a.b).g(new com.quizlet.data.repository.searchexplanations.c(21, this, models));
                Intrinsics.checkNotNullExpressionValue(gVarG2, "map(...)");
                g gVarE4 = new w(1, gVarG2, objC).e(new com.google.firebase.messaging.p(this, 25));
                Intrinsics.checkNotNullExpressionValue(gVarE4, "flatMap(...)");
                return gVarE4;
            case 4:
                ArrayList arrayListM2 = assistantMode.refactored.a.m("models", models);
                Iterator it7 = models.iterator();
                while (it7.hasNext()) {
                    User user = ((C4132h0) it7.next()).b;
                    if (user != null) {
                        arrayListM2.add(user);
                    }
                }
                p pVarA = ((a) this.c).a(arrayListM2);
                ArrayList arrayList4 = new ArrayList(C.q(models, 10));
                Iterator it8 = models.iterator();
                while (it8.hasNext()) {
                    arrayList4.add(((C4132h0) it8.next()).a);
                }
                w wVar = new w(1, ((a) this.b).a(arrayList4), new io.reactivex.rxjava3.internal.operators.completable.c(pVarA, 6));
                Intrinsics.checkNotNullExpressionValue(wVar, "andThen(...)");
                return d(wVar);
            case 5:
                ArrayList arrayListM3 = assistantMode.refactored.a.m("models", models);
                for (Object obj2 : models) {
                    if (((StudySet) obj2).x != 0) {
                        arrayListM3.add(obj2);
                    }
                }
                ArrayList models3 = new ArrayList(C.q(arrayListM3, 10));
                Iterator it9 = arrayListM3.iterator();
                while (it9.hasNext()) {
                    models3.add(com.quizlet.local.ormlite.models.set.a.b((StudySet) it9.next()));
                }
                q qVar = (q) this.d;
                Intrinsics.checkNotNullParameter(models3, "models");
                if (models3.isEmpty()) {
                    objC2 = io.reactivex.rxjava3.internal.operators.completable.f.a;
                    Intrinsics.checkNotNullExpressionValue(objC2, "complete(...)");
                } else {
                    Object value = ((u) qVar.b).getValue();
                    Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
                    Intrinsics.checkNotNullParameter(models3, "models");
                    objC2 = com.quizlet.local.ormlite.util.b.c((Dao) value, CollectionsKt.S(models3, null, null, null, new C4566c0(11), 31));
                }
                ArrayList arrayList5 = new ArrayList(C.q(models, 10));
                Iterator it10 = models.iterator();
                while (it10.hasNext()) {
                    arrayList5.add(Long.valueOf(((StudySet) it10.next()).a));
                }
                g gVarG3 = qVar.k(arrayList5).g(com.quizlet.local.ormlite.models.set.a.a).g(new l(this, false, models, 23));
                Intrinsics.checkNotNullExpressionValue(gVarG3, "map(...)");
                g gVarE5 = new w(1, gVarG3, objC2).e(new com.lyft.android.scissors.b(this, 25));
                Intrinsics.checkNotNullExpressionValue(gVarE5, "flatMap(...)");
                return gVarE5;
            default:
                Intrinsics.checkNotNullParameter(models, "models");
                ArrayList arrayList6 = new ArrayList(C.q(models, 10));
                Iterator it11 = models.iterator();
                while (it11.hasNext()) {
                    arrayList6.add(b.P((User) it11.next()));
                }
                g gVarE6 = ((ModelIdentityProvider) this.b).generateLocalIdsIfNeededAsync(arrayList6).e(new f(this, 23));
                Intrinsics.checkNotNullExpressionValue(gVarE6, "flatMap(...)");
                return gVarE6;
        }
    }

    public p b(List ids) {
        switch (this.a) {
            case 3:
                Intrinsics.checkNotNullParameter(ids, "ids");
                return AbstractC3771z.b((com.quizlet.local.ormlite.models.folder.a) this.c, (io.reactivex.rxjava3.internal.operators.flowable.b) ((c) this.d).k(ids));
            case 4:
                Intrinsics.checkNotNullParameter(ids, "ids");
                return d(((a) this.b).b(ids));
            case 5:
                Intrinsics.checkNotNullParameter(ids, "ids");
                g gVarG = ((q) this.d).k(ids).g(new c((com.quizlet.local.ormlite.models.set.a) this.c, 29));
                Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
                return gVarG;
            default:
                Intrinsics.checkNotNullParameter(ids, "ids");
                return AbstractC3771z.b((b) this.c, (io.reactivex.rxjava3.internal.operators.flowable.b) ((com.quizlet.local.ormlite.database.dao.b) this.d).a(ids));
        }
    }

    public p c(long j) {
        return AbstractC3771z.b((h) this.c, com.quizlet.local.ormlite.util.b.b(((com.lyft.android.scissors.b) this.d).g(), x.c("\n                SELECT * FROM group_folder\n                WHERE groupId = " + j + "\n                AND isDeleted = 0\n        ")));
    }

    public p d(p pVar) {
        g gVarG = pVar.g(com.quizlet.local.ormlite.models.folderwithcreator.a.b);
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        g gVarE = gVarG.g(com.quizlet.local.ormlite.models.folderwithcreator.a.c).e(new com.google.firebase.crashlytics.internal.settings.b(this, 27));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        p pVarP = p.p(gVarG, gVarE, new com.quizlet.data.interactor.course.a(this, 20));
        Intrinsics.checkNotNullExpressionValue(pVarP, "Single.zip(s1, s2, BiFun…-> zipper.invoke(t, u) })");
        return pVarP;
    }

    public g e(AbstractC4119d0 model) {
        Intrinsics.checkNotNullParameter(model, "model");
        Intrinsics.checkNotNullParameter(model, "model");
        return AbstractC3770y6.c(new z0(1, this, com.quizlet.data.repository.base.a.class, "importModels", "importModels(Ljava/util/List;)Lio/reactivex/rxjava3/core/Single;", 0, 8), model);
    }

    public g f(List list, boolean z) {
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            D data = (D) it2.next();
            Intrinsics.checkNotNullParameter(data, "data");
            DBGroupFolder dBGroupFolder = new DBGroupFolder();
            Long l = data.a;
            if (l != null) {
                dBGroupFolder.setLocalId(l.longValue());
            }
            dBGroupFolder.setClassId(data.b);
            dBGroupFolder.setFolderId(data.c);
            dBGroupFolder.setCanEdit(data.d);
            dBGroupFolder.setTimestamp(data.e);
            Boolean bool = data.f;
            if (bool != null) {
                dBGroupFolder.setDeleted(bool.booleanValue());
            }
            Long l2 = data.g;
            if (l2 != null) {
                dBGroupFolder.setClientTimestamp(l2.longValue());
            }
            dBGroupFolder.setLastModified(data.h);
            dBGroupFolder.setDirty(data.i);
            if (z) {
                dBGroupFolder.setDirty(true);
            }
            arrayList.add(dBGroupFolder);
        }
        ArrayList classFolderIds = new ArrayList(C.q(arrayList, 10));
        Iterator it3 = arrayList.iterator();
        while (it3.hasNext()) {
            DBGroupFolder dBGroupFolder2 = (DBGroupFolder) it3.next();
            classFolderIds.add(new com.quizlet.data.repository.classfolder.a(dBGroupFolder2.getClassId(), dBGroupFolder2.getFolderId()));
        }
        com.lyft.android.scissors.b bVar = (com.lyft.android.scissors.b) this.d;
        bVar.getClass();
        Intrinsics.checkNotNullParameter(classFolderIds, "ids");
        Dao daoG = bVar.g();
        Intrinsics.checkNotNullParameter(classFolderIds, "classFolderIds");
        String strS = classFolderIds.isEmpty() ? "0" : CollectionsKt.S(classFolderIds, "OR", "(", ")", new C4566c0(8), 24);
        g gVarG = com.quizlet.local.ormlite.util.b.b(daoG, x.c("\n                SELECT * FROM group_folder\n                WHERE " + strS + "\n                AND " + A.a(false) + "\n            ")).g(new com.google.mlkit.vision.documentscanner.internal.c(this, 26));
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        g gVarE = gVarG.g(new v(22, arrayList, this)).e(new com.lyft.android.scissors.b((ModelIdentityProvider) this.b, 23));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        g gVarE2 = gVarE.e(new com.quizlet.data.interactor.course.a(this, 19));
        Intrinsics.checkNotNullExpressionValue(gVarE2, "flatMap(...)");
        return gVarE2;
    }

    public a(s database, ModelIdentityProvider modelIdentityProvider, com.google.mlkit.common.sdkinternal.b mapper) {
        Intrinsics.checkNotNullParameter(database, "database");
        Intrinsics.checkNotNullParameter(modelIdentityProvider, "modelIdentityProvider");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        this.b = modelIdentityProvider;
        this.c = mapper;
        this.d = (com.quizlet.local.ormlite.database.dao.b) database.b;
    }

    public a(s database, ModelIdentityProvider modelIdentityProvider, com.quizlet.local.ormlite.models.folder.a mapper, com.quizlet.local.ormlite.models.folder.a newFolderMapper) {
        Intrinsics.checkNotNullParameter(database, "database");
        Intrinsics.checkNotNullParameter(modelIdentityProvider, "modelIdentityProvider");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        Intrinsics.checkNotNullParameter(newFolderMapper, "newFolderMapper");
        this.b = modelIdentityProvider;
        this.c = mapper;
        this.d = (c) database.c;
    }

    public a(s database, ModelIdentityProvider modelIdentityProvider, com.quizlet.local.ormlite.models.set.a mapper) {
        Intrinsics.checkNotNullParameter(database, "database");
        Intrinsics.checkNotNullParameter(modelIdentityProvider, "modelIdentityProvider");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        this.b = modelIdentityProvider;
        this.c = mapper;
        this.d = (q) database.a;
    }

    public a(s database, ModelIdentityProvider modelIdentityProvider, h mapper) {
        Intrinsics.checkNotNullParameter(database, "database");
        Intrinsics.checkNotNullParameter(modelIdentityProvider, "modelIdentityProvider");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        this.b = modelIdentityProvider;
        this.c = mapper;
        this.d = (com.lyft.android.scissors.b) database.d;
    }

    public a(s database, ModelIdentityProvider modelIdentityProvider, com.quizlet.shared.usecase.folderstudymaterials.b mapper) {
        Intrinsics.checkNotNullParameter(database, "database");
        Intrinsics.checkNotNullParameter(modelIdentityProvider, "modelIdentityProvider");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        this.b = modelIdentityProvider;
        this.c = mapper;
        this.d = (com.quizlet.data.interactor.course.a) database.f;
    }

    public a(a folderLocal, a userLocal, a bookmarkLocal) {
        Intrinsics.checkNotNullParameter(folderLocal, "folderLocal");
        Intrinsics.checkNotNullParameter(userLocal, "userLocal");
        Intrinsics.checkNotNullParameter(bookmarkLocal, "bookmarkLocal");
        this.b = folderLocal;
        this.c = userLocal;
        this.d = bookmarkLocal;
    }
}
