package com.quizlet.data.repository.classfolder;

import androidx.compose.animation.core.O0;
import assistantMode.types.z;
import com.bumptech.glide.manager.p;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3763y;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z;
import com.onetrust.otpublishers.headless.Internal.Helper.h;
import com.quizlet.data.model.D;
import com.quizlet.db.data.models.persisted.DBAnswer;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBAnswerFields;
import com.quizlet.db.data.models.persisted.fields.DBQuestionAttributeFields;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.generated.enums.A1;
import com.quizlet.infra.legacysyncengine.datasources.o;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.functions.j;
import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import io.reactivex.rxjava3.internal.operators.single.g;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.A;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements j {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ long b;
    public final /* synthetic */ ArrayList c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ c(e eVar, List list, ArrayList arrayList, long j) {
        this.d = eVar;
        this.e = list;
        this.c = arrayList;
        this.b = j;
    }

    @Override // io.reactivex.rxjava3.functions.j
    public final Object get() {
        switch (this.a) {
            case 0:
                e eVar = (e) this.d;
                com.quizlet.data.repository.explanations.myexplanations.a aVar = (com.quizlet.data.repository.explanations.myexplanations.a) eVar.b;
                com.quizlet.local.ormlite.models.bookmark.a aVar2 = (com.quizlet.local.ormlite.models.bookmark.a) aVar.b;
                ArrayList arrayList = this.c;
                List list = (List) this.e;
                final List folderIds = CollectionsKt.b0(list, arrayList);
                Intrinsics.checkNotNullParameter(folderIds, "folderIdsToUndelete");
                final long j = this.b;
                List groupIds = A.b(Long.valueOf(j));
                final int i = 1;
                Function1 function1 = new Function1() { // from class: com.quizlet.local.ormlite.models.classfolder.a
                    @Override // kotlin.jvm.functions.Function1
                    public final Object invoke(Object obj) {
                        List deletedLocalClassFolders = (List) obj;
                        switch (i) {
                            case 0:
                                Intrinsics.checkNotNullParameter(deletedLocalClassFolders, "deletedLocalClassFolders");
                                ArrayList arrayList2 = new ArrayList(C.q(deletedLocalClassFolders, 10));
                                Iterator it2 = deletedLocalClassFolders.iterator();
                                while (it2.hasNext()) {
                                    arrayList2.add(Long.valueOf(((D) it2.next()).c));
                                }
                                return new b(CollectionsKt.b0(folderIds, arrayList2), A.b(Long.valueOf(j)));
                            default:
                                Intrinsics.checkNotNullParameter(deletedLocalClassFolders, "undeletedLocalClassFolders");
                                ArrayList arrayList3 = new ArrayList(C.q(deletedLocalClassFolders, 10));
                                Iterator it3 = deletedLocalClassFolders.iterator();
                                while (it3.hasNext()) {
                                    arrayList3.add(Long.valueOf(((D) it3.next()).c));
                                }
                                return new b(CollectionsKt.b0(folderIds, arrayList3), A.b(Long.valueOf(j)));
                        }
                    }
                };
                com.lyft.android.scissors.b bVar = (com.lyft.android.scissors.b) aVar2.d;
                Intrinsics.checkNotNullParameter(folderIds, "folderIds");
                Intrinsics.checkNotNullParameter(groupIds, "groupIds");
                g gVarB = AbstractC3771z.b((h) aVar2.c, com.quizlet.local.ormlite.util.b.b(bVar.g(), AbstractC3763y.b(folderIds, groupIds, false)));
                g gVarE = gVarB.e(new p((Object) function1, (Object) aVar2, false));
                Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
                io.reactivex.rxjava3.core.p pVarP = io.reactivex.rxjava3.core.p.p(gVarB, gVarE, new com.google.mlkit.common.sdkinternal.model.a(28));
                Intrinsics.checkNotNullExpressionValue(pVarP, "Single.zip(s1, s2, BiFun…-> zipper.invoke(t, u) })");
                g gVar = new g(pVarP, new com.quizlet.data.repository.qclass.c(18, eVar, "Error creating/updating undeleted ClassFolders"), 2);
                Intrinsics.checkNotNullExpressionValue(gVar, "onErrorResumeNext(...)");
                com.quizlet.local.ormlite.models.bookmark.a aVar3 = (com.quizlet.local.ormlite.models.bookmark.a) aVar.b;
                final List folderIds2 = CollectionsKt.b0(arrayList, list);
                Intrinsics.checkNotNullParameter(folderIds2, "folderIdsToDelete");
                List groupIds2 = A.b(Long.valueOf(j));
                final int i2 = 0;
                Function1 function12 = new Function1() { // from class: com.quizlet.local.ormlite.models.classfolder.a
                    @Override // kotlin.jvm.functions.Function1
                    public final Object invoke(Object obj) {
                        List deletedLocalClassFolders = (List) obj;
                        switch (i2) {
                            case 0:
                                Intrinsics.checkNotNullParameter(deletedLocalClassFolders, "deletedLocalClassFolders");
                                ArrayList arrayList2 = new ArrayList(C.q(deletedLocalClassFolders, 10));
                                Iterator it2 = deletedLocalClassFolders.iterator();
                                while (it2.hasNext()) {
                                    arrayList2.add(Long.valueOf(((D) it2.next()).c));
                                }
                                return new b(CollectionsKt.b0(folderIds2, arrayList2), A.b(Long.valueOf(j)));
                            default:
                                Intrinsics.checkNotNullParameter(deletedLocalClassFolders, "undeletedLocalClassFolders");
                                ArrayList arrayList3 = new ArrayList(C.q(deletedLocalClassFolders, 10));
                                Iterator it3 = deletedLocalClassFolders.iterator();
                                while (it3.hasNext()) {
                                    arrayList3.add(Long.valueOf(((D) it3.next()).c));
                                }
                                return new b(CollectionsKt.b0(folderIds2, arrayList3), A.b(Long.valueOf(j)));
                        }
                    }
                };
                com.lyft.android.scissors.b bVar2 = (com.lyft.android.scissors.b) aVar3.d;
                Intrinsics.checkNotNullParameter(folderIds2, "folderIds");
                Intrinsics.checkNotNullParameter(groupIds2, "groupIds");
                g gVarB2 = AbstractC3771z.b((h) aVar3.c, com.quizlet.local.ormlite.util.b.b(bVar2.g(), AbstractC3763y.b(folderIds2, groupIds2, true)));
                g gVarE2 = gVarB2.e(new p((Object) function12, (Object) aVar3, true));
                Intrinsics.checkNotNullExpressionValue(gVarE2, "flatMap(...)");
                io.reactivex.rxjava3.core.p pVarP2 = io.reactivex.rxjava3.core.p.p(gVarB2, gVarE2, new com.google.mlkit.common.sdkinternal.model.a(28));
                Intrinsics.checkNotNullExpressionValue(pVarP2, "Single.zip(s1, s2, BiFun…-> zipper.invoke(t, u) })");
                g gVar2 = new g(pVarP2, new com.quizlet.data.repository.qclass.c(18, eVar, "Error creating/updating deleted ClassFolders"), 2);
                Intrinsics.checkNotNullExpressionValue(gVar2, "onErrorResumeNext(...)");
                io.reactivex.rxjava3.core.p pVarP3 = io.reactivex.rxjava3.core.p.p(gVar, gVar2, new d());
                Intrinsics.checkNotNullExpressionValue(pVarP3, "Single.zip(s1, s2, BiFun…-> zipper.invoke(t, u) })");
                g gVarE3 = pVarP3.e(new com.lyft.android.scissors.b(eVar, 9));
                Intrinsics.checkNotNullExpressionValue(gVarE3, "flatMap(...)");
                g gVar3 = new g(gVarE3, new com.quizlet.data.repository.qclass.c(18, eVar, "Error attempting to update a single Folder in a multiple classes"), 2);
                Intrinsics.checkNotNullExpressionValue(gVar3, "onErrorResumeNext(...)");
                return gVar3;
            default:
                com.quizlet.data.repository.explanations.textbook.a aVar4 = (com.quizlet.data.repository.explanations.textbook.a) this.d;
                com.quizlet.infra.legacysyncengine.orm.b bVar3 = new com.quizlet.infra.legacysyncengine.orm.b(Models.ANSWER);
                bVar3.b(Long.valueOf(this.b), DBAnswerFields.SESSION);
                Relationship<DBAnswer, DBUser> relationship = DBAnswerFields.PERSON;
                com.quizlet.infra.legacysyncengine.managers.d dVar = (com.quizlet.infra.legacysyncengine.managers.d) aVar4.b;
                bVar3.b(Long.valueOf(dVar.e.getPersonId()), relationship);
                bVar3.b(Long.valueOf(A1.FLASHCARDS.a()), DBAnswerFields.MODE_TYPE);
                com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar3.a();
                Intrinsics.checkNotNullExpressionValue(aVarA, "build(...)");
                com.quizlet.infra.legacysyncengine.net.c cVar = (com.quizlet.infra.legacysyncengine.net.c) aVar4.a;
                o oVar = new o(cVar, aVarA);
                aVar4.c = oVar;
                oVar.d();
                z zVar = (z) this.e;
                com.quizlet.infra.legacysyncengine.orm.b bVar4 = new com.quizlet.infra.legacysyncengine.orm.b(Models.QUESTION_ATTRIBUTE);
                bVar4.b(Long.valueOf(zVar.a), DBQuestionAttributeFields.SET_ID);
                bVar4.b(Long.valueOf(dVar.e.getPersonId()), DBQuestionAttributeFields.PERSON_ID);
                com.quizlet.infra.legacysyncengine.orm.query.a aVarA2 = bVar4.a();
                Intrinsics.checkNotNullExpressionValue(aVarA2, "build(...)");
                o oVar2 = new o(cVar, aVarA2);
                aVar4.d = oVar2;
                oVar2.d();
                o oVar3 = (o) aVar4.c;
                if (oVar3 == null) {
                    Intrinsics.m("answersDataSource");
                    throw null;
                }
                C4887f c4887f = new C4887f(oVar3.f(), 5);
                o oVar4 = (o) aVar4.d;
                if (oVar4 == null) {
                    Intrinsics.m("questionAttributeDataSource");
                    throw null;
                }
                return new io.reactivex.rxjava3.internal.operators.observable.C(i.y(c4887f, new C4887f(oVar4.f(), 5), new O0(this.c)), io.reactivex.rxjava3.internal.functions.d.d, new com.quizlet.eventlogger.e(aVar4, 4));
        }
    }

    public /* synthetic */ c(com.quizlet.data.repository.explanations.textbook.a aVar, long j, z zVar, ArrayList arrayList) {
        this.d = aVar;
        this.b = j;
        this.e = zVar;
        this.c = arrayList;
    }
}
