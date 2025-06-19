package com.google.android.material.floatingactionbutton;

import android.content.Context;
import android.util.Log;
import android.view.ViewGroup;
import androidx.compose.foundation.text.input.internal.u;
import androidx.datastore.core.InterfaceC1076h;
import androidx.lifecycle.B;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.U;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3738u6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3770y6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z;
import com.google.android.gms.tasks.Task;
import com.j256.ormlite.dao.Dao;
import com.quizlet.data.model.AbstractC4119d0;
import com.quizlet.data.model.C4135i0;
import com.quizlet.data.model.G;
import com.quizlet.data.model.Q;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBTermFields;
import com.quizlet.features.setpage.viewmodel.P;
import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import io.reactivex.rxjava3.internal.operators.observable.E;
import io.reactivex.rxjava3.internal.operators.observable.J;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import kotlin.collections.A;
import kotlin.collections.C;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.x;

/* loaded from: classes2.dex */
public final class c implements g, com.google.android.gms.tasks.e, com.google.android.gms.tasks.d, com.google.android.gms.tasks.c, com.google.android.gms.tasks.b, com.google.common.util.concurrent.c, io.reactivex.rxjava3.functions.h, com.quizlet.local.ormlite.database.b {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ c(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object a(com.quizlet.features.setpage.header.ui.a r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r5 = this;
            boolean r0 = r7 instanceof com.quizlet.features.setpage.menu.data.l
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.features.setpage.menu.data.l r0 = (com.quizlet.features.setpage.menu.data.l) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            com.quizlet.features.setpage.menu.data.l r0 = new com.quizlet.features.setpage.menu.data.l
            r0.<init>(r5, r7)
        L18:
            java.lang.Object r7 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            int r6 = r0.l
            com.quizlet.features.setpage.data.b r1 = r0.k
            kotlin.jvm.functions.Function0 r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L54
        L2d:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            com.quizlet.features.setpage.data.b r7 = com.quizlet.features.setpage.data.b.c
            r0.j = r6
            r0.k = r7
            r2 = 2131231424(0x7f0802c0, float:1.8078929E38)
            r0.l = r2
            r0.o = r3
            java.lang.Object r4 = r5.b
            com.quizlet.data.repository.set.f r4 = (com.quizlet.data.repository.set.f) r4
            java.lang.Object r0 = r4.c(r0)
            if (r0 != r1) goto L50
            return r1
        L50:
            r1 = r7
            r7 = r0
            r0 = r6
            r6 = r2
        L54:
            com.quizlet.featuregate.contracts.enums.a r7 = (com.quizlet.featuregate.contracts.enums.a) r7
            r1.getClass()
            java.lang.String r1 = "alternateStudyModeNamesType"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r1)
            int[] r1 = com.quizlet.features.setpage.data.c.a
            int r7 = r7.ordinal()
            r7 = r1[r7]
            if (r7 != r3) goto L6c
            r7 = 2132018114(0x7f1403c2, float:1.9674526E38)
            goto L6f
        L6c:
            r7 = 2132018102(0x7f1403b6, float:1.9674501E38)
        L6f:
            com.quizlet.uicommon.ui.common.overflowmenu.f r1 = new com.quizlet.uicommon.ui.common.overflowmenu.f
            r1.<init>(r6, r7, r0)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.floatingactionbutton.c.a(com.quizlet.features.setpage.header.ui.a, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        io.reactivex.rxjava3.core.i iVarP;
        switch (this.a) {
            case 8:
                List contentFoldersWithCreator = (List) obj;
                Intrinsics.checkNotNullParameter(contentFoldersWithCreator, "contentFoldersWithCreator");
                com.quizlet.data.repository.folderwithcreator.e eVar = (com.quizlet.data.repository.folderwithcreator.e) this.b;
                ArrayList arrayList = new ArrayList();
                for (Object obj2 : contentFoldersWithCreator) {
                    if (((G) obj2).a.x == null) {
                        arrayList.add(obj2);
                    }
                }
                ArrayList folderIds = new ArrayList(C.q(arrayList, 10));
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    folderIds.add(Long.valueOf(((G) it2.next()).a.l));
                }
                if (folderIds.isEmpty()) {
                    iVarP = io.reactivex.rxjava3.core.i.p(V.c());
                } else {
                    com.quizlet.data.repository.folderset.c cVar = (com.quizlet.data.repository.folderset.c) eVar.c;
                    Intrinsics.checkNotNullParameter(folderIds, "folderIds");
                    com.quizlet.data.repository.explanations.myexplanations.a aVar = (com.quizlet.data.repository.explanations.myexplanations.a) ((com.onetrust.otpublishers.headless.UI.fragment.q) cVar.b).b;
                    Intrinsics.checkNotNullParameter(folderIds, "folderIds");
                    com.quizlet.quizletandroid.ui.setcreation.managers.n nVar = (com.quizlet.quizletandroid.ui.setcreation.managers.n) aVar.b;
                    Intrinsics.checkNotNullParameter(folderIds, "folderIds");
                    io.reactivex.rxjava3.internal.operators.single.g gVarG = ((com.quizlet.remote.service.n) nVar.b).c(U.c(folderIds), null).g(new com.quizlet.remote.model.folderset.a(aVar, null));
                    Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
                    iVarP = new J(cVar.n(gVarG), new com.google.firebase.crashlytics.internal.settings.b(cVar, 13), 4).q(com.quizlet.data.repository.folderset.b.c);
                    Intrinsics.checkNotNullExpressionValue(iVarP, "map(...)");
                }
                return iVarP.q(new com.quizlet.data.interactor.folderwithcreatorinclass.a(eVar, contentFoldersWithCreator));
            case 9:
            case 11:
            case 17:
            case 18:
            case 19:
            case 20:
            case 21:
            case EventType.WINDOW_STATE /* 22 */:
            case EventType.SUBS /* 25 */:
            case EventType.CDN /* 26 */:
            default:
                List p0 = (List) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                return AbstractC3771z.c((com.quizlet.local.ormlite.models.set.a) this.b, p0);
            case 10:
                Throwable it3 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                ((org.slf4j.b) ((com.quizlet.data.interactor.progress.c) this.b).d).h("Error retrieving cached progress reset data", it3);
                return Q.a;
            case 12:
                List it4 = (List) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                return ((com.quizlet.local.ormlite.models.bookmark.a) ((com.quizlet.data.repository.explanations.myexplanations.a) ((com.quizlet.data.repository.classfolder.e) this.b).b).b).a(it4);
            case 13:
                AbstractC4119d0 savedFolder = (AbstractC4119d0) obj;
                Intrinsics.checkNotNullParameter(savedFolder, "savedFolder");
                com.quizlet.data.repository.folder.i iVar = (com.quizlet.data.repository.folder.i) this.b;
                return new io.reactivex.rxjava3.internal.operators.single.g(AbstractC3738u6.b(iVar.b, new com.quizlet.data.repository.explanations.exercise.a(3, iVar, savedFolder), new com.quizlet.assembly.compose.listitems.r(17)), new com.quizlet.data.repository.searchexplanations.c(17, iVar, savedFolder), 2);
            case 14:
                Throwable e = (Throwable) obj;
                Intrinsics.checkNotNullParameter(e, "e");
                ((org.slf4j.b) ((com.quizlet.data.repository.folderwithcreator.e) this.b).d).j("no cached object", e);
                return E.a;
            case 15:
                Throwable e2 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(e2, "e");
                ((org.slf4j.b) ((com.quizlet.data.repository.set.f) this.b).d).j("no network connection", e2);
                return io.reactivex.rxjava3.core.p.d(e2);
            case 16:
                C4135i0 it5 = (C4135i0) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                com.quizlet.data.repository.user.a aVar2 = (com.quizlet.data.repository.user.a) ((com.quizlet.data.repository.activitycenter.b) ((com.quizlet.data.repository.user.a) this.b).b).b;
                List users = A.b(it5);
                Intrinsics.checkNotNullParameter(users, "users");
                ArrayList arrayList2 = new ArrayList(C.q(users, 10));
                Iterator it6 = users.iterator();
                while (it6.hasNext()) {
                    arrayList2.add(retrofit2.adapter.rxjava3.d.t((C4135i0) it6.next()));
                }
                io.reactivex.rxjava3.internal.operators.single.g gVarE = ((ModelIdentityProvider) aVar2.b).generateLocalIdsIfNeededAsync(arrayList2).e(new com.google.firebase.crashlytics.internal.settings.b(aVar2, 29));
                Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
                return AbstractC3770y6.a(gVarE);
            case EventType.AUDIO /* 23 */:
                Boolean canShowAds = (Boolean) obj;
                Intrinsics.checkNotNullParameter(canShowAds, "canShowAds");
                if (!canShowAds.booleanValue()) {
                    return E.a;
                }
                P p = (P) this.b;
                J jQ = ((io.reactivex.rxjava3.subjects.d) p.H1.h).l(com.quizlet.features.setpage.data.b.a).q(com.quizlet.features.setpage.data.b.b);
                Intrinsics.checkNotNullExpressionValue(jQ, "map(...)");
                return jQ;
            case EventType.VIDEO /* 24 */:
                DBStudySet set = (DBStudySet) obj;
                Intrinsics.checkNotNullParameter(set, "set");
                com.quizlet.infra.legacysyncengine.net.c cVar2 = (com.quizlet.infra.legacysyncengine.net.c) ((com.quizlet.data.repository.folderwithcreatorinclass.e) this.b).b;
                com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.TERM);
                bVar.b(Long.valueOf(set.getId()), DBTermFields.SET);
                bVar.e(DBTermFields.DEFINITION_IMAGE);
                return cVar2.b(bVar.a(), com.quizlet.infra.legacysyncengine.net.b.b).g(new com.google.firebase.crashlytics.internal.common.j(set, 20));
            case 27:
                List modelsWithIds = (List) obj;
                Intrinsics.checkNotNullParameter(modelsWithIds, "modelsWithIds");
                com.quizlet.local.ormlite.models.bookmark.a aVar3 = (com.quizlet.local.ormlite.models.bookmark.a) this.b;
                return new io.reactivex.rxjava3.internal.operators.completable.m(((com.quizlet.local.ormlite.database.dao.b) aVar3.d).f(modelsWithIds), null, Boolean.TRUE, 0).g(new androidx.work.impl.model.l(modelsWithIds, false, aVar3, 22));
            case 28:
                List modelsWithIds2 = (List) obj;
                Intrinsics.checkNotNullParameter(modelsWithIds2, "modelsWithIds");
                com.quizlet.local.ormlite.models.bookmark.a aVar4 = (com.quizlet.local.ormlite.models.bookmark.a) this.b;
                return new io.reactivex.rxjava3.internal.operators.completable.m(((c) aVar4.d).f(modelsWithIds2), null, Boolean.TRUE, 0).g(new u(modelsWithIds2, false, aVar4, 21));
        }
    }

    @Override // com.google.android.material.floatingactionbutton.g
    public int b() {
        return ((ExtendedFloatingActionButton) this.b).getMeasuredHeight();
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object c(com.quizlet.data.model.A0 r5, com.quizlet.features.setpage.header.ui.a r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.features.setpage.menu.data.m
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.features.setpage.menu.data.m r0 = (com.quizlet.features.setpage.menu.data.m) r0
            int r1 = r0.p
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.p = r1
            goto L18
        L13:
            com.quizlet.features.setpage.menu.data.m r0 = new com.quizlet.features.setpage.menu.data.m
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.n
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.p
            r3 = 1
            if (r2 == 0) goto L37
            if (r2 != r3) goto L2f
            int r5 = r0.m
            com.quizlet.features.setpage.data.b r6 = r0.l
            kotlin.jvm.functions.Function0 r1 = r0.k
            com.quizlet.data.model.A0 r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L59
        L2f:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L37:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            com.quizlet.features.setpage.data.b r7 = com.quizlet.features.setpage.data.b.c
            r0.j = r5
            r0.k = r6
            r0.l = r7
            r2 = 2131231428(0x7f0802c4, float:1.8078937E38)
            r0.m = r2
            r0.p = r3
            java.lang.Object r3 = r4.b
            com.quizlet.data.repository.set.f r3 = (com.quizlet.data.repository.set.f) r3
            java.lang.Object r0 = r3.c(r0)
            if (r0 != r1) goto L54
            return r1
        L54:
            r1 = r6
            r6 = r7
            r7 = r0
            r0 = r5
            r5 = r2
        L59:
            com.quizlet.featuregate.contracts.enums.a r7 = (com.quizlet.featuregate.contracts.enums.a) r7
            r6.getClass()
            int r6 = com.quizlet.features.setpage.data.b.a(r7)
            com.quizlet.uicommon.ui.common.overflowmenu.f r7 = new com.quizlet.uicommon.ui.common.overflowmenu.f
            r7.<init>(r5, r6, r0, r1)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.floatingactionbutton.c.c(com.quizlet.data.model.A0, com.quizlet.features.setpage.header.ui.a, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object d(com.quizlet.features.setpage.header.ui.a r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r5 = this;
            boolean r0 = r7 instanceof com.quizlet.features.setpage.menu.data.n
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.features.setpage.menu.data.n r0 = (com.quizlet.features.setpage.menu.data.n) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            com.quizlet.features.setpage.menu.data.n r0 = new com.quizlet.features.setpage.menu.data.n
            r0.<init>(r5, r7)
        L18:
            java.lang.Object r7 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            int r6 = r0.l
            com.quizlet.features.setpage.data.b r1 = r0.k
            kotlin.jvm.functions.Function0 r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L54
        L2d:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            com.quizlet.features.setpage.data.b r7 = com.quizlet.features.setpage.data.b.c
            r0.j = r6
            r0.k = r7
            r2 = 2131231432(0x7f0802c8, float:1.8078945E38)
            r0.l = r2
            r0.o = r3
            java.lang.Object r4 = r5.b
            com.quizlet.data.repository.set.f r4 = (com.quizlet.data.repository.set.f) r4
            java.lang.Object r0 = r4.c(r0)
            if (r0 != r1) goto L50
            return r1
        L50:
            r1 = r7
            r7 = r0
            r0 = r6
            r6 = r2
        L54:
            com.quizlet.featuregate.contracts.enums.a r7 = (com.quizlet.featuregate.contracts.enums.a) r7
            r1.getClass()
            java.lang.String r1 = "alternateStudyModeNamesType"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r1)
            int[] r1 = com.quizlet.features.setpage.data.c.a
            int r7 = r7.ordinal()
            r7 = r1[r7]
            if (r7 != r3) goto L6c
            r7 = 2132018826(0x7f14068a, float:1.967597E38)
            goto L6f
        L6c:
            r7 = 2132018817(0x7f140681, float:1.9675951E38)
        L6f:
            com.quizlet.uicommon.ui.common.overflowmenu.f r1 = new com.quizlet.uicommon.ui.common.overflowmenu.f
            r1.<init>(r6, r7, r0)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.floatingactionbutton.c.d(com.quizlet.features.setpage.header.ui.a, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object e(com.quizlet.data.model.A0 r6, com.quizlet.features.setpage.header.ui.a r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r5 = this;
            boolean r0 = r8 instanceof com.quizlet.features.setpage.menu.data.o
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.features.setpage.menu.data.o r0 = (com.quizlet.features.setpage.menu.data.o) r0
            int r1 = r0.p
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.p = r1
            goto L18
        L13:
            com.quizlet.features.setpage.menu.data.o r0 = new com.quizlet.features.setpage.menu.data.o
            r0.<init>(r5, r8)
        L18:
            java.lang.Object r8 = r0.n
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.p
            r3 = 1
            if (r2 == 0) goto L37
            if (r2 != r3) goto L2f
            int r6 = r0.m
            com.quizlet.features.setpage.data.b r7 = r0.l
            kotlin.jvm.functions.Function0 r1 = r0.k
            com.quizlet.data.model.A0 r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L59
        L2f:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L37:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.quizlet.features.setpage.data.b r8 = com.quizlet.features.setpage.data.b.c
            r0.j = r6
            r0.k = r7
            r0.l = r8
            r2 = 2131231438(0x7f0802ce, float:1.8078957E38)
            r0.m = r2
            r0.p = r3
            java.lang.Object r4 = r5.b
            com.quizlet.data.repository.set.f r4 = (com.quizlet.data.repository.set.f) r4
            java.lang.Object r0 = r4.c(r0)
            if (r0 != r1) goto L54
            return r1
        L54:
            r1 = r7
            r7 = r8
            r8 = r0
            r0 = r6
            r6 = r2
        L59:
            com.quizlet.featuregate.contracts.enums.a r8 = (com.quizlet.featuregate.contracts.enums.a) r8
            r7.getClass()
            java.lang.String r7 = "alternateStudyModeNamesType"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r7)
            int[] r7 = com.quizlet.features.setpage.data.c.a
            int r8 = r8.ordinal()
            r7 = r7[r8]
            if (r7 != r3) goto L71
            r7 = 2132019894(0x7f140ab6, float:1.9678136E38)
            goto L74
        L71:
            r7 = 2132019892(0x7f140ab4, float:1.9678132E38)
        L74:
            com.quizlet.uicommon.ui.common.overflowmenu.f r8 = new com.quizlet.uicommon.ui.common.overflowmenu.f
            r8.<init>(r6, r7, r0, r1)
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.floatingactionbutton.c.e(com.quizlet.data.model.A0, com.quizlet.features.setpage.header.ui.a, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // com.quizlet.local.ormlite.database.b
    public io.reactivex.rxjava3.internal.operators.completable.c f(List models) {
        Intrinsics.checkNotNullParameter(models, "models");
        return com.quizlet.local.ormlite.util.b.a(h(), models);
    }

    @Override // com.google.android.gms.tasks.e
    public Task g(Object obj) throws NumberFormatException, ClassNotFoundException {
        if (((com.google.firebase.crashlytics.internal.settings.a) obj) == null) {
            Log.w("FirebaseCrashlytics", "Received null app settings at app startup. Cannot send cached reports", null);
            return S3.i(null);
        }
        com.quizlet.data.interactor.school.b bVar = (com.quizlet.data.interactor.school.b) this.b;
        com.google.firebase.crashlytics.internal.common.m.a((com.google.firebase.crashlytics.internal.common.m) bVar.c);
        com.google.firebase.crashlytics.internal.common.m mVar = (com.google.firebase.crashlytics.internal.common.m) bVar.c;
        mVar.m.n(null, mVar.e.a);
        mVar.q.d(null);
        return S3.i(null);
    }

    @Override // com.google.android.material.floatingactionbutton.g
    public ViewGroup.LayoutParams getLayoutParams() {
        return new ViewGroup.LayoutParams(-2, -2);
    }

    @Override // com.google.android.material.floatingactionbutton.g
    public int getWidth() {
        ExtendedFloatingActionButton extendedFloatingActionButton = (ExtendedFloatingActionButton) this.b;
        return (extendedFloatingActionButton.getMeasuredWidth() - (extendedFloatingActionButton.getCollapsedPadding() * 2)) + extendedFloatingActionButton.z + extendedFloatingActionButton.A;
    }

    public Dao h() {
        Object value = ((kotlin.u) this.b).getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        return (Dao) value;
    }

    @Override // com.google.android.material.floatingactionbutton.g
    public int i() {
        return ((ExtendedFloatingActionButton) this.b).A;
    }

    @Override // com.google.android.gms.tasks.b
    public void j() {
        ((CountDownLatch) this.b).countDown();
    }

    public io.reactivex.rxjava3.core.p k(List ids) {
        Intrinsics.checkNotNullParameter(ids, "ids");
        Dao daoH = h();
        Intrinsics.checkNotNullParameter(ids, "ids");
        return com.quizlet.local.ormlite.util.b.b(daoH, x.c("\n                SELECT * FROM folder\n                WHERE id IN " + com.google.android.gms.internal.mlkit_vision_document_scanner.A.b(ids) + "\n                AND isDeleted = 0\n        "));
    }

    /* JADX WARN: Code restructure failed: missing block: B:32:0x008d, code lost:
    
        if (r9 == r1) goto L33;
     */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0071  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0092  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object l(long r8, boolean r10, kotlin.coroutines.jvm.internal.c r11) throws java.lang.Throwable {
        /*
            r7 = this;
            boolean r0 = r11 instanceof com.quizlet.features.folders.viewmodel.usecases.s
            if (r0 == 0) goto L13
            r0 = r11
            com.quizlet.features.folders.viewmodel.usecases.s r0 = (com.quizlet.features.folders.viewmodel.usecases.s) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            com.quizlet.features.folders.viewmodel.usecases.s r0 = new com.quizlet.features.folders.viewmodel.usecases.s
            r0.<init>(r7, r11)
        L18:
            java.lang.Object r11 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 0
            r4 = 2
            r5 = 0
            r6 = 1
            if (r2 == 0) goto L3f
            if (r2 == r6) goto L37
            if (r2 != r4) goto L2f
            int r8 = r0.l
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L90
        L2f:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L37:
            long r8 = r0.k
            com.google.android.material.floatingactionbutton.c r10 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L5f
        L3f:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            if (r10 == 0) goto L6b
            r0.j = r7
            r0.k = r8
            r0.o = r6
            java.lang.Object r10 = r7.b
            com.quizlet.data.repository.activitycenter.b r10 = (com.quizlet.data.repository.activitycenter.b) r10
            com.quizlet.data.interactor.folder.q r11 = new com.quizlet.data.interactor.folder.q
            r11.<init>(r10, r8, r5)
            java.lang.Object r10 = r10.c
            kotlinx.coroutines.y r10 = (kotlinx.coroutines.AbstractC5040y) r10
            java.lang.Object r11 = kotlinx.coroutines.E.J(r10, r11, r0)
            if (r11 != r1) goto L5e
            goto L8f
        L5e:
            r10 = r7
        L5f:
            java.lang.Boolean r11 = (java.lang.Boolean) r11
            boolean r11 = r11.booleanValue()
            if (r11 != 0) goto L6c
            r11 = r10
            r9 = r8
            r8 = r6
            goto L6f
        L6b:
            r10 = r7
        L6c:
            r11 = r10
            r9 = r8
            r8 = r3
        L6f:
            if (r8 == 0) goto L90
            java.lang.Object r11 = r11.b
            com.quizlet.data.repository.activitycenter.b r11 = (com.quizlet.data.repository.activitycenter.b) r11
            r0.j = r5
            r0.l = r8
            r0.o = r4
            com.quizlet.data.interactor.folder.r r2 = new com.quizlet.data.interactor.folder.r
            r2.<init>(r11, r9, r5)
            java.lang.Object r9 = r11.c
            kotlinx.coroutines.y r9 = (kotlinx.coroutines.AbstractC5040y) r9
            java.lang.Object r9 = kotlinx.coroutines.E.J(r9, r2, r0)
            if (r9 != r1) goto L8b
            goto L8d
        L8b:
            kotlin.Unit r9 = kotlin.Unit.a
        L8d:
            if (r9 != r1) goto L90
        L8f:
            return r1
        L90:
            if (r8 == 0) goto L93
            r3 = r6
        L93:
            java.lang.Boolean r8 = java.lang.Boolean.valueOf(r3)
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.floatingactionbutton.c.l(long, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object m(java.lang.String r5, kotlin.coroutines.jvm.internal.c r6, boolean r7) throws java.lang.Throwable {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.data.interactor.notes.i
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.data.interactor.notes.i r0 = (com.quizlet.data.interactor.notes.i) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.notes.i r0 = new com.quizlet.data.interactor.notes.i
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.glance.appwidget.protobuf.Z.e(r6)     // Catch: java.lang.Exception -> L27
            goto L50
        L27:
            r5 = move-exception
            goto L53
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.lang.Object r6 = r4.b     // Catch: java.lang.Exception -> L27
            com.quizlet.remote.model.notes.e r6 = (com.quizlet.remote.model.notes.e) r6     // Catch: java.lang.Exception -> L27
            r0.l = r3     // Catch: java.lang.Exception -> L27
            com.quizlet.remote.model.notes.c r2 = new com.quizlet.remote.model.notes.c     // Catch: java.lang.Exception -> L27
            r3 = 0
            r2.<init>(r6, r5, r3, r7)     // Catch: java.lang.Exception -> L27
            java.lang.Object r5 = r6.c     // Catch: java.lang.Exception -> L27
            kotlinx.coroutines.y r5 = (kotlinx.coroutines.AbstractC5040y) r5     // Catch: java.lang.Exception -> L27
            java.lang.Object r5 = kotlinx.coroutines.E.J(r5, r2, r0)     // Catch: java.lang.Exception -> L27
            if (r5 != r1) goto L4b
            goto L4d
        L4b:
            kotlin.Unit r5 = kotlin.Unit.a     // Catch: java.lang.Exception -> L27
        L4d:
            if (r5 != r1) goto L50
            return r1
        L50:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        L53:
            com.quizlet.data.exceptions.notes.UpdatePrivacySettingsException r6 = new com.quizlet.data.exceptions.notes.UpdatePrivacySettingsException
            java.lang.String r5 = r5.getMessage()
            r6.<init>(r5)
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.floatingactionbutton.c.m(java.lang.String, kotlin.coroutines.jvm.internal.c, boolean):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object n(kotlin.coroutines.jvm.internal.c r7) {
        /*
            r6 = this;
            boolean r0 = r7 instanceof com.quizlet.data.interactor.achievements.o
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.data.interactor.achievements.o r0 = (com.quizlet.data.interactor.achievements.o) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.data.interactor.achievements.o r0 = new com.quizlet.data.interactor.achievements.o
            r0.<init>(r6, r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 0
            r4 = 1
            if (r2 == 0) goto L32
            if (r2 != r4) goto L2a
            com.google.android.material.floatingactionbutton.c r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L54
        L2a:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L32:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.j = r6
            r0.m = r4
            java.lang.Object r7 = r6.b
            com.google.firebase.messaging.p r7 = (com.google.firebase.messaging.p) r7
            java.time.LocalDate r2 = java.time.LocalDate.now()
            java.lang.String r4 = "now(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r2, r4)
            com.quizlet.data.interactor.achievements.m r4 = new com.quizlet.data.interactor.achievements.m
            r5 = 0
            r4.<init>(r7, r2, r3, r5)
            java.lang.Object r7 = kotlinx.coroutines.E.m(r4, r0)
            if (r7 != r1) goto L53
            return r1
        L53:
            r0 = r6
        L54:
            com.quizlet.data.interactor.achievements.g r7 = (com.quizlet.data.interactor.achievements.g) r7
            boolean r1 = r7.d
            if (r1 == 0) goto L5b
            return r3
        L5b:
            r0.getClass()
            com.quizlet.data.model.g r0 = r7.a
            boolean r1 = r0 instanceof com.quizlet.data.model.C4106a
            if (r1 == 0) goto L67
            com.quizlet.data.model.a r0 = (com.quizlet.data.model.C4106a) r0
            goto L7f
        L67:
            boolean r1 = r0 instanceof com.quizlet.data.model.C4118d
            if (r1 != 0) goto L7e
            com.quizlet.data.model.f r1 = com.quizlet.data.model.C4125f.a
            boolean r1 = kotlin.jvm.internal.Intrinsics.b(r0, r1)
            if (r1 != 0) goto L7e
            boolean r0 = r0 instanceof com.quizlet.data.model.C4122e
            if (r0 == 0) goto L78
            goto L7e
        L78:
            kotlin.NoWhenBranchMatchedException r7 = new kotlin.NoWhenBranchMatchedException
            r7.<init>()
            throw r7
        L7e:
            r0 = r3
        L7f:
            com.quizlet.data.model.s r1 = r7.c
            boolean r2 = r1 instanceof com.quizlet.data.model.C4155p
            if (r2 == 0) goto L88
            com.quizlet.data.model.p r1 = (com.quizlet.data.model.C4155p) r1
            goto L9c
        L88:
            boolean r2 = r1 instanceof com.quizlet.data.model.C4158q
            if (r2 != 0) goto L9b
            com.quizlet.data.model.r r2 = com.quizlet.data.model.r.a
            boolean r1 = kotlin.jvm.internal.Intrinsics.b(r1, r2)
            if (r1 == 0) goto L95
            goto L9b
        L95:
            kotlin.NoWhenBranchMatchedException r7 = new kotlin.NoWhenBranchMatchedException
            r7.<init>()
            throw r7
        L9b:
            r1 = r3
        L9c:
            com.quizlet.data.model.h2 r7 = r7.b
            boolean r2 = r7 instanceof com.quizlet.data.model.C4121d2
            if (r2 == 0) goto La6
            r3 = r7
            com.quizlet.data.model.d2 r3 = (com.quizlet.data.model.C4121d2) r3
            goto Lbd
        La6:
            boolean r2 = r7 instanceof com.quizlet.data.model.e2
            if (r2 != 0) goto Lbd
            boolean r2 = r7 instanceof com.quizlet.data.model.f2
            if (r2 != 0) goto Lbd
            com.quizlet.data.model.g2 r2 = com.quizlet.data.model.g2.a
            boolean r7 = kotlin.jvm.internal.Intrinsics.b(r7, r2)
            if (r7 == 0) goto Lb7
            goto Lbd
        Lb7:
            kotlin.NoWhenBranchMatchedException r7 = new kotlin.NoWhenBranchMatchedException
            r7.<init>()
            throw r7
        Lbd:
            com.quizlet.data.interactor.achievements.i r7 = new com.quizlet.data.interactor.achievements.i
            r7.<init>(r0, r1, r3)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.floatingactionbutton.c.n(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public io.reactivex.rxjava3.core.p o(androidx.work.impl.model.c userProps) {
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = com.google.android.gms.dynamite.d.e(((assistantMode.utils.studiableMetadata.b) this.b).L(userProps));
        C4887f c4887f = (C4887f) userProps.c;
        c4887f.getClass();
        io.reactivex.rxjava3.internal.operators.single.g gVarE2 = new io.reactivex.rxjava3.internal.operators.flowable.b(new C4887f(c4887f, 5), 2).e(new com.quizlet.featuregate.features.folder.b(userProps, 2));
        Intrinsics.checkNotNullExpressionValue(gVarE2, "flatMap(...)");
        return com.google.android.gms.dynamite.d.b(gVarE, gVarE2);
    }

    @Override // com.google.common.util.concurrent.c
    public void onFailure(Throwable th) {
        com.quizlet.data.repository.widget.b bVar = com.google.mlkit.vision.camera.a.l;
        String localizedMessage = th.getLocalizedMessage();
        if (Log.isLoggable((String) bVar.b, 6)) {
            Log.e("CameraXSource", bVar.t(localizedMessage));
        }
        com.google.mlkit.vision.camera.a aVar = (com.google.mlkit.vision.camera.a) this.b;
        aVar.h.g(B.c);
        aVar.d(302);
    }

    @Override // com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        switch (this.a) {
            case 2:
                ((CountDownLatch) this.b).countDown();
                break;
            default:
                com.google.mlkit.vision.camera.a aVar = (com.google.mlkit.vision.camera.a) this.b;
                aVar.g.a(new com.google.android.gms.tasks.k(this, false, (androidx.camera.lifecycle.g) obj, 5), androidx.core.content.c.d((Context) aVar.f.c));
                break;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object p(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.quizlet.features.infra.google.f
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.features.infra.google.f r0 = (com.quizlet.features.infra.google.f) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.infra.google.f r0 = new com.quizlet.features.infra.google.f
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.glance.appwidget.protobuf.Z.e(r5)     // Catch: java.lang.Throwable -> L27
            goto L48
        L27:
            r5 = move-exception
            goto L4d
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            kotlin.p r5 = kotlin.r.b     // Catch: java.lang.Throwable -> L27
            java.lang.Object r5 = r4.b     // Catch: java.lang.Throwable -> L27
            androidx.credentials.f r5 = (androidx.credentials.f) r5     // Catch: java.lang.Throwable -> L27
            androidx.credentials.a r2 = new androidx.credentials.a     // Catch: java.lang.Throwable -> L27
            r2.<init>()     // Catch: java.lang.Throwable -> L27
            r0.l = r3     // Catch: java.lang.Throwable -> L27
            java.lang.Object r5 = r5.a(r2, r0)     // Catch: java.lang.Throwable -> L27
            if (r5 != r1) goto L48
            return r1
        L48:
            kotlin.Unit r5 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L27
            kotlin.p r0 = kotlin.r.b     // Catch: java.lang.Throwable -> L27
            return r5
        L4d:
            kotlin.p r0 = kotlin.r.b
            kotlin.q r5 = androidx.glance.appwidget.protobuf.Z.b(r5)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.floatingactionbutton.c.p(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // com.google.android.gms.tasks.c
    public void t(Exception exc) {
        ((CountDownLatch) this.b).countDown();
    }

    @Override // com.google.android.material.floatingactionbutton.g
    public int v() {
        return ((ExtendedFloatingActionButton) this.b).z;
    }

    public c(com.perimeterx.mobile_sdk.web_view_interception.c stage) {
        this.a = 4;
        Intrinsics.checkNotNullParameter(stage, "stage");
        this.b = stage;
    }

    public c(com.quizlet.data.repository.activitycenter.b folderOnboardingUseCase) {
        this.a = 19;
        Intrinsics.checkNotNullParameter(folderOnboardingUseCase, "folderOnboardingUseCase");
        this.b = folderOnboardingUseCase;
    }

    public c(com.quizlet.data.repository.classfolder.e repository) {
        this.a = 7;
        Intrinsics.checkNotNullParameter(repository, "repository");
        this.b = repository;
    }

    public c(com.quizlet.local.datastore.models.metering.i soundEffectsRepository) {
        this.a = 11;
        Intrinsics.checkNotNullParameter(soundEffectsRepository, "soundEffectsRepository");
        this.b = soundEffectsRepository;
    }

    public c(com.quizlet.remote.model.notes.e notesRepository) {
        this.a = 9;
        Intrinsics.checkNotNullParameter(notesRepository, "notesRepository");
        this.b = notesRepository;
    }

    public c(assistantMode.utils.studiableMetadata.b imageUploadFeature) {
        this.a = 18;
        Intrinsics.checkNotNullParameter(imageUploadFeature, "imageUploadFeature");
        this.b = imageUploadFeature;
    }

    public c(com.quizlet.shared.usecase.srs.a userCanEditGroupFeature) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(userCanEditGroupFeature, "userCanEditGroupFeature");
        this.b = userCanEditGroupFeature;
    }

    public c(androidx.credentials.f credentialManager) {
        this.a = 20;
        Intrinsics.checkNotNullParameter(credentialManager, "credentialManager");
        this.b = credentialManager;
    }

    public c(com.quizlet.data.repository.set.f alternateStudyModeNamesType) {
        this.a = 22;
        Intrinsics.checkNotNullParameter(alternateStudyModeNamesType, "alternateStudyModeNamesType");
        this.b = alternateStudyModeNamesType;
    }

    public c(com.quizlet.billing.manager.sku.a skuResolver) {
        this.a = 5;
        Intrinsics.checkNotNullParameter(skuResolver, "skuResolver");
        this.b = skuResolver;
    }

    public c(com.google.firebase.messaging.p achievementsUseCase) {
        this.a = 6;
        Intrinsics.checkNotNullParameter(achievementsUseCase, "achievementsUseCase");
        this.b = achievementsUseCase;
    }

    public c(u matchGameDataProviderFactory) {
        this.a = 21;
        Intrinsics.checkNotNullParameter(matchGameDataProviderFactory, "matchGameDataProviderFactory");
        this.b = matchGameDataProviderFactory;
    }

    public c(DatabaseHelper database) {
        this.a = 26;
        Intrinsics.checkNotNullParameter(database, "database");
        this.b = kotlin.l.b(new com.quizlet.local.ormlite.database.dao.a(database, 1));
    }

    public c(InterfaceC1076h dataStore) {
        this.a = 25;
        Intrinsics.checkNotNullParameter(dataStore, "dataStore");
        this.b = dataStore;
    }

    public c() {
        this.a = 2;
        this.b = new CountDownLatch(1);
    }
}
