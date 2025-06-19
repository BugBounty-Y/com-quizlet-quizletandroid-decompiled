package com.quizlet.quizletandroid.ui.library;

import androidx.lifecycle.m0;
import androidx.lifecycle.w0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3682n5;
import com.quizlet.data.model.EnumC4164s0;
import com.quizlet.data.model.S1;
import com.quizlet.data.model.T1;
import com.quizlet.data.model.User;
import com.quizlet.data.model.Y1;
import com.quizlet.edgy.ui.viewmodel.C4203d;
import com.quizlet.eventlogger.features.folder.FolderLogger;
import com.quizlet.quizletandroid.ui.library.data.C4652f;
import com.quizlet.quizletandroid.ui.library.data.C4655i;
import com.quizlet.quizletandroid.ui.library.data.C4656j;
import com.quizlet.quizletandroid.ui.library.data.C4657k;
import com.quizlet.quizletandroid.ui.library.data.C4658l;
import com.quizlet.quizletandroid.ui.library.data.C4659m;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class c0 extends w0 implements InterfaceC4646d {
    public final long b;
    public final com.quizlet.data.interactor.folderwithcreator.m c;
    public final com.google.android.gms.measurement.internal.J d;
    public final com.quizlet.quizletandroid.interactor.m e;
    public final com.onetrust.otpublishers.headless.UI.fragment.q f;
    public final androidx.work.impl.model.c g;
    public final com.quizlet.offline.managers.b h;
    public final com.quizlet.library.logging.b i;
    public final com.google.firebase.crashlytics.internal.settings.b j;
    public final com.quizlet.quizletandroid.interactor.p k;
    public final com.google.firebase.crashlytics.internal.common.j l;
    public final com.quizlet.featuregate.features.folder.e m;
    public final FolderLogger n;
    public final androidx.work.impl.model.e o;
    public final androidx.work.impl.model.v p;
    public final com.quizlet.data.repository.user.a q;
    public final com.quizlet.features.infra.basestudy.manager.d r;
    public final EnumC4164s0 s;
    public final s0 t;
    public final d0 u;
    public List v;
    public Y1 w;
    public String x;
    public boolean y;
    public final C4203d z;

    public c0(m0 savedStateHandle, long j, com.quizlet.data.interactor.folderwithcreator.m getFoldersWithCreatorUseCase, com.google.android.gms.measurement.internal.J getAllClassCardUseCase, com.quizlet.quizletandroid.interactor.m getAllStudySetsCardWithCreatorUseCase, com.onetrust.otpublishers.headless.UI.fragment.q getBucketedSetsBySectionsUseCase, androidx.work.impl.model.c userProperties, com.quizlet.offline.managers.b offlineStateManager, com.quizlet.library.logging.b eventLogger, com.google.firebase.crashlytics.internal.settings.b checkNotesEligibilityUseCase, com.quizlet.quizletandroid.interactor.p getLastVisitedLibraryTabUseCase, com.google.firebase.crashlytics.internal.common.j saveLastVisitedLibraryTabUseCase, com.quizlet.featuregate.features.folder.e folderEligibility, FolderLogger folderEventLogger, androidx.work.impl.model.e practiceTestUploadFeature, androidx.work.impl.model.v getPracticeTestsLibraryTabEligibilityUseCase, com.quizlet.data.repository.user.a libraryRedesignFeature, com.quizlet.features.infra.basestudy.manager.d studyFunnelEventManager) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(getFoldersWithCreatorUseCase, "getFoldersWithCreatorUseCase");
        Intrinsics.checkNotNullParameter(getAllClassCardUseCase, "getAllClassCardUseCase");
        Intrinsics.checkNotNullParameter(getAllStudySetsCardWithCreatorUseCase, "getAllStudySetsCardWithCreatorUseCase");
        Intrinsics.checkNotNullParameter(getBucketedSetsBySectionsUseCase, "getBucketedSetsBySectionsUseCase");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(offlineStateManager, "offlineStateManager");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(checkNotesEligibilityUseCase, "checkNotesEligibilityUseCase");
        Intrinsics.checkNotNullParameter(getLastVisitedLibraryTabUseCase, "getLastVisitedLibraryTabUseCase");
        Intrinsics.checkNotNullParameter(saveLastVisitedLibraryTabUseCase, "saveLastVisitedLibraryTabUseCase");
        Intrinsics.checkNotNullParameter(folderEligibility, "folderEligibility");
        Intrinsics.checkNotNullParameter(folderEventLogger, "folderEventLogger");
        Intrinsics.checkNotNullParameter(practiceTestUploadFeature, "practiceTestUploadFeature");
        Intrinsics.checkNotNullParameter(getPracticeTestsLibraryTabEligibilityUseCase, "getPracticeTestsLibraryTabEligibilityUseCase");
        Intrinsics.checkNotNullParameter(libraryRedesignFeature, "libraryRedesignFeature");
        Intrinsics.checkNotNullParameter(studyFunnelEventManager, "studyFunnelEventManager");
        this.b = j;
        this.c = getFoldersWithCreatorUseCase;
        this.d = getAllClassCardUseCase;
        this.e = getAllStudySetsCardWithCreatorUseCase;
        this.f = getBucketedSetsBySectionsUseCase;
        this.g = userProperties;
        this.h = offlineStateManager;
        this.i = eventLogger;
        this.j = checkNotesEligibilityUseCase;
        this.k = getLastVisitedLibraryTabUseCase;
        this.l = saveLastVisitedLibraryTabUseCase;
        this.m = folderEligibility;
        this.n = folderEventLogger;
        this.o = practiceTestUploadFeature;
        this.p = getPracticeTestsLibraryTabEligibilityUseCase;
        this.q = libraryRedesignFeature;
        this.r = studyFunnelEventManager;
        this.s = (EnumC4164s0) savedStateHandle.a("startTab");
        this.t = e0.c(new com.quizlet.quizletandroid.ui.library.data.J(kotlin.collections.K.a, EnumC4164s0.a, com.quizlet.quizletandroid.ui.library.data.I.a, C4655i.a, C4652f.a, false, false, false));
        this.u = e0.b(0, 0, null, 7);
        this.v = kotlin.collections.K.a;
        this.w = Y1.a;
        this.x = "";
        this.z = new C4203d(this);
        studyFunnelEventManager.a();
    }

    /* JADX WARN: Code restructure failed: missing block: B:23:0x0062, code lost:
    
        if (r9.emit(r10, r0) == r1) goto L39;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x009e, code lost:
    
        if (r9.emit(r11, r0) == r1) goto L39;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x00b7, code lost:
    
        if (r9.emit(r2, r0) == r1) goto L39;
     */
    /* JADX WARN: Removed duplicated region for block: B:32:0x008b  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x00a4  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object A(com.quizlet.quizletandroid.ui.library.c0 r9, com.quizlet.ui.models.content.carditem.f r10, kotlin.coroutines.jvm.internal.c r11) {
        /*
            r9.getClass()
            boolean r0 = r11 instanceof com.quizlet.quizletandroid.ui.library.L
            if (r0 == 0) goto L16
            r0 = r11
            com.quizlet.quizletandroid.ui.library.L r0 = (com.quizlet.quizletandroid.ui.library.L) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.n = r1
            goto L1b
        L16:
            com.quizlet.quizletandroid.ui.library.L r0 = new com.quizlet.quizletandroid.ui.library.L
            r0.<init>(r9, r11)
        L1b:
            java.lang.Object r11 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 4
            r4 = 3
            r5 = 2
            r6 = 1
            if (r2 == 0) goto L4c
            if (r2 == r6) goto L48
            if (r2 == r5) goto L40
            if (r2 == r4) goto L3c
            if (r2 != r3) goto L34
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto Lba
        L34:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L3c:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto La1
        L40:
            com.quizlet.ui.models.content.carditem.f r10 = r0.k
            com.quizlet.quizletandroid.ui.library.c0 r9 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L7f
        L48:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L65
        L4c:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            boolean r11 = r10.g
            long r7 = r10.a
            if (r11 == 0) goto L68
            kotlinx.coroutines.flow.d0 r9 = r9.u
            com.quizlet.quizletandroid.ui.library.data.r r10 = new com.quizlet.quizletandroid.ui.library.data.r
            r10.<init>(r7)
            r0.n = r6
            java.lang.Object r9 = r9.emit(r10, r0)
            if (r9 != r1) goto L65
            goto Lb9
        L65:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        L68:
            com.quizlet.offline.managers.b r11 = r9.h
            com.quizlet.offline.managers.i r11 = (com.quizlet.offline.managers.i) r11
            boolean r2 = r10.k
            io.reactivex.rxjava3.internal.operators.single.k r11 = r11.a(r7, r2)
            r0.j = r9
            r0.k = r10
            r0.n = r5
            java.lang.Object r11 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r11, r0)
            if (r11 != r1) goto L7f
            goto Lb9
        L7f:
            java.lang.String r2 = "await(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r11, r2)
            com.quizlet.offline.managers.j r11 = (com.quizlet.offline.managers.j) r11
            com.quizlet.offline.managers.j r2 = com.quizlet.offline.managers.j.a
            r5 = 0
            if (r11 != r2) goto La4
            kotlinx.coroutines.flow.d0 r9 = r9.u
            com.quizlet.quizletandroid.ui.library.data.B r11 = new com.quizlet.quizletandroid.ui.library.data.B
            long r2 = r10.a
            r11.<init>(r2)
            r0.j = r5
            r0.k = r5
            r0.n = r4
            java.lang.Object r9 = r9.emit(r11, r0)
            if (r9 != r1) goto La1
            goto Lb9
        La1:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        La4:
            kotlinx.coroutines.flow.d0 r9 = r9.u
            com.quizlet.quizletandroid.ui.library.data.z r2 = new com.quizlet.quizletandroid.ui.library.data.z
            long r6 = r10.a
            r2.<init>(r6, r11)
            r0.j = r5
            r0.k = r5
            r0.n = r3
            java.lang.Object r9 = r9.emit(r2, r0)
            if (r9 != r1) goto Lba
        Lb9:
            return r1
        Lba:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.library.c0.A(com.quizlet.quizletandroid.ui.library.c0, com.quizlet.ui.models.content.carditem.f, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static Long D(com.quizlet.quizletandroid.ui.library.data.p pVar) {
        if (pVar instanceof C4657k) {
            com.quizlet.quizletandroid.ui.library.data.K k = ((C4657k) pVar).b;
            com.quizlet.quizletandroid.ui.library.data.L l = k instanceof com.quizlet.quizletandroid.ui.library.data.L ? (com.quizlet.quizletandroid.ui.library.data.L) k : null;
            if (l != null) {
                return Long.valueOf(l.b.a);
            }
            return null;
        }
        if (pVar instanceof C4658l) {
            return Long.valueOf(((C4658l) pVar).b.b.a);
        }
        if (pVar instanceof com.quizlet.quizletandroid.ui.library.data.o) {
            return Long.valueOf(((com.quizlet.quizletandroid.ui.library.data.o) pVar).b.b.a);
        }
        if ((pVar instanceof C4656j) || (pVar instanceof C4659m) || (pVar instanceof com.quizlet.quizletandroid.ui.library.data.n)) {
            return null;
        }
        throw new NoWhenBranchMatchedException();
    }

    public final void B() {
        ArrayList arrayList;
        s0 s0Var;
        Object value;
        List list = this.v;
        if (this.w == Y1.a) {
            HashSet hashSet = new HashSet();
            arrayList = new ArrayList();
            for (Object obj : list) {
                if (hashSet.add(Long.valueOf(((S1) obj).a.a))) {
                    arrayList.add(obj);
                }
            }
        } else {
            arrayList = new ArrayList();
            for (Object obj2 : list) {
                if (((S1) obj2).a.i == this.w) {
                    arrayList.add(obj2);
                }
            }
        }
        ArrayList arrayList2 = new ArrayList();
        for (Object obj3 : arrayList) {
            if (StringsKt.G(((S1) obj3).a.b, this.x, true)) {
                arrayList2.add(obj3);
            }
        }
        kotlinx.collections.immutable.e studySetList = AbstractC3409x1.k(arrayList2);
        com.onetrust.otpublishers.headless.UI.fragment.q qVar = this.f;
        qVar.getClass();
        Intrinsics.checkNotNullParameter(studySetList, "studySetList");
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        long jCurrentTimeMillis = System.currentTimeMillis();
        boolean z = false;
        ListIterator listIterator = ((kotlinx.collections.immutable.implementations.immutableList.a) studySetList).listIterator(0);
        while (listIterator.hasNext()) {
            S1 s1 = (S1) listIterator.next();
            com.quizlet.data.model.I i = s1.a;
            if (i.g) {
                com.onetrust.otpublishers.headless.UI.fragment.q.l(linkedHashMap, 0L, s1);
            } else {
                com.onetrust.otpublishers.headless.UI.fragment.q.l(linkedHashMap, ((com.quizlet.quizletandroid.util.o) qVar.b).a(jCurrentTimeMillis, i.h * 1000), s1);
            }
        }
        ArrayList arrayList3 = new ArrayList(linkedHashMap.size());
        for (Map.Entry entry : linkedHashMap.entrySet()) {
            arrayList3.add(new T1(((Number) entry.getKey()).longValue(), (List) entry.getValue()));
        }
        Intrinsics.checkNotNullParameter(arrayList3, "<this>");
        ArrayList arrayList4 = new ArrayList();
        Iterator it2 = arrayList3.iterator();
        while (it2.hasNext()) {
            T1 t1 = (T1) it2.next();
            arrayList4.add(new com.quizlet.quizletandroid.ui.library.data.M(t1.a));
            for (S1 s12 : t1.b) {
                com.quizlet.ui.models.content.carditem.f fVarB = AbstractC3682n5.b(s12);
                User user = s12.b;
                boolean z2 = user.a == this.b ? true : z;
                com.quizlet.data.model.I i2 = s12.a;
                Intrinsics.checkNotNullParameter(i2, "<this>");
                arrayList4.add(new com.quizlet.quizletandroid.ui.library.data.L(fVarB, new com.quizlet.ui.models.content.listitem.d(i2.c, i2.a, i2.b, user.b, z2, i2.g), i2.h, i2.i));
                z = false;
            }
        }
        kotlinx.collections.immutable.b bVarI = AbstractC3409x1.i(arrayList4);
        do {
            s0Var = this.t;
            value = s0Var.getValue();
        } while (!s0Var.k(value, com.quizlet.quizletandroid.ui.library.data.J.a((com.quizlet.quizletandroid.ui.library.data.J) value, null, null, new com.quizlet.quizletandroid.ui.library.data.G(bVarI, studySetList.isEmpty()), null, null, false, false, false, 251)));
    }

    public final void C(int i, String str) {
        try {
            this.r.d(i, str);
        } catch (Exception e) {
            timber.log.c.a.f(e, "Failed to log impressed item clicked", new Object[0]);
        }
    }
}
