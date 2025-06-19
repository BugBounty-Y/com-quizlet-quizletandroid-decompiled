package com.quizlet.data.repository.login;

import android.os.Handler;
import androidx.appcompat.app.J;
import androidx.camera.core.impl.utils.executor.d;
import androidx.concurrent.futures.j;
import androidx.lifecycle.A;
import androidx.lifecycle.L;
import androidx.paging.J0;
import androidx.work.impl.model.c;
import com.google.android.gms.internal.mlkit_common.u;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3406w2;
import com.google.android.gms.internal.mlkit_vision_camera.L1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.C3618f5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.C3676n;
import com.google.android.gms.internal.mlkit_vision_document_scanner.C3684o;
import com.google.firebase.encoders.EncodingException;
import com.quizlet.data.model.K0;
import com.quizlet.data.model.S;
import com.quizlet.data.model.Y0;
import com.quizlet.generated.enums.C4531x0;
import com.quizlet.generated.enums.EnumC4533y0;
import com.quizlet.generated.enums.H;
import com.quizlet.quizletandroid.interactor.t;
import com.quizlet.quizletandroid.ui.activitycenter.views.i;
import com.quizlet.quizletandroid.ui.profile.b;
import com.quizlet.remote.model.practicetests.PracticeTestGradedQuestionResponse;
import com.quizlet.remote.model.practicetests.PracticeTestResult;
import com.quizlet.remote.model.practicetests.RemotePracticeTestResultResponse;
import com.quizlet.remote.model.practicetests.RemotePracticeTestSetId;
import io.reactivex.rxjava3.core.p;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.collections.U;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import org.koin.core.error.DefinitionOverrideException;

/* loaded from: classes2.dex */
public class a implements j, com.quizlet.mapper.a {
    public Object a;
    public Object b;
    public Object c;

    public /* synthetic */ a(Object obj, Object obj2, Object obj3) {
        this.a = obj;
        this.b = obj2;
        this.c = obj3;
    }

    @Override // com.quizlet.mapper.a
    public Object a(Object obj) {
        RemotePracticeTestResultResponse input = (RemotePracticeTestResultResponse) obj;
        Intrinsics.checkNotNullParameter(input, "input");
        PracticeTestResult practiceTestResult = (PracticeTestResult) CollectionsKt.L(input.d.a);
        S s = (S) ((b) this.c).a(CollectionsKt.L(input.d.b));
        ArrayList arrayList = new ArrayList();
        Iterator it2 = practiceTestResult.a.iterator();
        while (it2.hasNext()) {
            arrayList.add(((i) this.a).a((PracticeTestGradedQuestionResponse) it2.next()));
        }
        RemotePracticeTestSetId remotePracticeTestSetId = practiceTestResult.f;
        K0 k0 = (K0) ((com.quizlet.quizletandroid.ui.setcreation.adapters.a) this.b).a(practiceTestResult.e);
        Map map = practiceTestResult.g;
        LinkedHashMap linkedHashMap = new LinkedHashMap(U.a(map.size()));
        for (Map.Entry entry : map.entrySet()) {
            C4531x0 c4531x0 = EnumC4533y0.Companion;
            String str = (String) entry.getKey();
            c4531x0.getClass();
            linkedHashMap.put(C4531x0.a(str), entry.getValue());
        }
        return new Y0(arrayList, practiceTestResult.d, practiceTestResult.b, practiceTestResult.c, k0, remotePracticeTestSetId.a, linkedHashMap, s);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object b(androidx.work.impl.model.c r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.featuregate.features.region.b
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.featuregate.features.region.b r0 = (com.quizlet.featuregate.features.region.b) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.featuregate.features.region.b r0 = new com.quizlet.featuregate.features.region.b
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            com.quizlet.data.repository.login.a r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L61
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r4
            r0.m = r3
            java.lang.Object r6 = r4.c
            com.quizlet.featuregate.features.region.a r6 = (com.quizlet.featuregate.features.region.a) r6
            int r6 = r6.ordinal()
            if (r6 == 0) goto L58
            if (r6 == r3) goto L53
            r0 = 2
            if (r6 != r0) goto L4d
            com.quizlet.generated.enums.H r5 = r5.g()
        L4b:
            r6 = r5
            goto L5d
        L4d:
            kotlin.NoWhenBranchMatchedException r5 = new kotlin.NoWhenBranchMatchedException
            r5.<init>()
            throw r5
        L53:
            java.lang.Enum r5 = r5.m(r0)
            goto L4b
        L58:
            java.lang.Enum r5 = r5.d(r0)
            goto L4b
        L5d:
            if (r6 != r1) goto L60
            return r1
        L60:
            r5 = r4
        L61:
            com.quizlet.generated.enums.H r6 = (com.quizlet.generated.enums.H) r6
            java.lang.Object r5 = r5.b
            java.util.List r5 = (java.util.List) r5
            boolean r5 = kotlin.collections.CollectionsKt.F(r5, r6)
            java.lang.Boolean r5 = java.lang.Boolean.valueOf(r5)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.login.a.b(androidx.work.impl.model.c, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r10v0, types: [com.quizlet.data.repository.login.a] */
    /* JADX WARN: Type inference failed for: r12v3, types: [java.util.List] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object c(com.quizlet.db.data.models.identity.ModelIdentityProvider r11, java.util.ArrayList r12, kotlin.coroutines.jvm.internal.c r13) {
        /*
            r10 = this;
            boolean r0 = r13 instanceof com.quizlet.local.ormlite.models.selectedterm.a
            if (r0 == 0) goto L13
            r0 = r13
            com.quizlet.local.ormlite.models.selectedterm.a r0 = (com.quizlet.local.ormlite.models.selectedterm.a) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.local.ormlite.models.selectedterm.a r0 = new com.quizlet.local.ormlite.models.selectedterm.a
            r0.<init>(r10, r13)
        L18:
            java.lang.Object r13 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3a
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r13)
            return r13
        L2a:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r12)
            throw r11
        L32:
            java.util.List r12 = r0.k
            com.quizlet.db.data.models.identity.ModelIdentityProvider r11 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L4a
        L3a:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            r0.j = r11
            r0.k = r12
            r0.n = r4
            java.io.Serializable r13 = r10.e(r12, r0)
            if (r13 != r1) goto L4a
            goto L8a
        L4a:
            java.util.Map r13 = (java.util.Map) r13
            java.util.Iterator r2 = r12.iterator()
        L50:
            boolean r4 = r2.hasNext()
            if (r4 == 0) goto L79
            java.lang.Object r4 = r2.next()
            com.quizlet.db.data.models.persisted.DBSelectedTerm r4 = (com.quizlet.db.data.models.persisted.DBSelectedTerm) r4
            com.quizlet.data.model.F1 r5 = new com.quizlet.data.model.F1
            long r6 = r4.getTermId()
            long r8 = r4.getPersonId()
            r5.<init>(r6, r8)
            java.lang.Object r5 = r13.get(r5)
            java.lang.Long r5 = (java.lang.Long) r5
            if (r5 == 0) goto L50
            long r5 = r5.longValue()
            r4.setLocalId(r5)
            goto L50
        L79:
            io.reactivex.rxjava3.core.p r11 = r11.generateLocalIdsIfNeededAsync(r12)
            r12 = 0
            r0.j = r12
            r0.k = r12
            r0.n = r3
            java.lang.Object r11 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r11, r0)
            if (r11 != r1) goto L8b
        L8a:
            return r1
        L8b:
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.login.a.c(com.quizlet.db.data.models.identity.ModelIdentityProvider, java.util.ArrayList, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // androidx.concurrent.futures.j
    public Object d(androidx.concurrent.futures.i iVar) {
        iVar.a(new J(this, 3), T.a());
        ((d) this.c).a.set(iVar);
        return "HandlerScheduledFuture-" + ((Callable) this.b).toString();
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.io.Serializable e(java.util.ArrayList r11, kotlin.coroutines.jvm.internal.c r12) {
        /*
            Method dump skipped, instructions count: 261
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.login.a.e(java.util.ArrayList, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.io.Serializable f(long r5, long r7, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r4 = this;
            boolean r0 = r9 instanceof com.quizlet.local.ormlite.models.selectedterm.c
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.local.ormlite.models.selectedterm.c r0 = (com.quizlet.local.ormlite.models.selectedterm.c) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.local.ormlite.models.selectedterm.c r0 = new com.quizlet.local.ormlite.models.selectedterm.c
            r0.<init>(r4, r9)
        L18:
            java.lang.Object r9 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            com.quizlet.data.repository.login.a r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L64
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r0.j = r4
            r0.m = r3
            java.lang.Object r9 = r4.c
            com.quizlet.data.interactor.achievements.f r9 = (com.quizlet.data.interactor.achievements.f) r9
            com.j256.ormlite.dao.Dao r9 = r9.g()
            java.lang.String r2 = "\n            SELECT * FROM selected_term\n            WHERE setId = "
            java.lang.String r3 = "\n            AND personId = "
            java.lang.StringBuilder r5 = androidx.compose.animation.d0.t(r5, r2, r3)
            r5.append(r7)
            java.lang.String r6 = "\n            AND isDeleted = 0\n        "
            r5.append(r6)
            java.lang.String r5 = r5.toString()
            java.lang.String r5 = kotlin.text.x.c(r5)
            io.reactivex.rxjava3.internal.operators.flowable.b r5 = com.quizlet.local.ormlite.util.b.b(r9, r5)
            java.lang.Object r9 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r5, r0)
            if (r9 != r1) goto L63
            return r1
        L63:
            r5 = r4
        L64:
            java.lang.Object r5 = r5.b
            com.quizlet.shared.usecase.folderstudymaterials.d r5 = (com.quizlet.shared.usecase.folderstudymaterials.d) r5
            java.util.List r9 = (java.util.List) r9
            java.util.ArrayList r5 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z.c(r5, r9)
            java.util.ArrayList r6 = new java.util.ArrayList
            r6.<init>()
            java.util.Iterator r5 = r5.iterator()
        L77:
            boolean r7 = r5.hasNext()
            if (r7 == 0) goto L89
            java.lang.Object r7 = r5.next()
            boolean r8 = r7 instanceof com.quizlet.data.model.E1
            if (r8 == 0) goto L77
            r6.add(r7)
            goto L77
        L89:
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.login.a.f(long, long, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r11v0, types: [com.quizlet.studiablemodels.grading.d] */
    /* JADX WARN: Type inference failed for: r13v2, types: [kotlin.jvm.functions.Function0] */
    /* JADX WARN: Type inference failed for: r14v2, types: [kotlin.jvm.functions.Function0] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object g(com.quizlet.studiablemodels.grading.d r11, com.quizlet.studiablemodels.grading.FillInTheBlankResponse r12, com.quizlet.features.notes.paywall.a r13, com.quizlet.features.notes.paywall.a r14, kotlin.coroutines.jvm.internal.c r15) {
        /*
            Method dump skipped, instructions count: 222
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.login.a.g(com.quizlet.studiablemodels.grading.d, com.quizlet.studiablemodels.grading.FillInTheBlankResponse, com.quizlet.features.notes.paywall.a, com.quizlet.features.notes.paywall.a, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0019  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object h(kotlin.coroutines.jvm.internal.c r8) {
        /*
            r7 = this;
            java.lang.String r0 = "UserInitializerHelper_initUser"
            com.google.firebase.perf.metrics.Trace r0 = com.google.firebase.perf.b.a(r0)
            boolean r1 = r8 instanceof com.quizlet.quizletandroid.initializers.app.i
            if (r1 == 0) goto L19
            r1 = r8
            com.quizlet.quizletandroid.initializers.app.i r1 = (com.quizlet.quizletandroid.initializers.app.i) r1
            int r2 = r1.m
            r3 = -2147483648(0xffffffff80000000, float:-0.0)
            r4 = r2 & r3
            if (r4 == 0) goto L19
            int r2 = r2 - r3
            r1.m = r2
            goto L1e
        L19:
            com.quizlet.quizletandroid.initializers.app.i r1 = new com.quizlet.quizletandroid.initializers.app.i
            r1.<init>(r7, r8)
        L1e:
            java.lang.Object r8 = r1.k
            kotlin.coroutines.intrinsics.a r2 = kotlin.coroutines.intrinsics.a.a
            int r3 = r1.m
            r4 = 1
            if (r3 == 0) goto L3a
            if (r3 != r4) goto L2f
            com.quizlet.data.repository.login.a r1 = r1.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L62
        L2f:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r1 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r1)
            r0.stop()
            throw r8
        L3a:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            java.lang.Object r8 = r7.a
            com.quizlet.quizletandroid.interactor.t r8 = (com.quizlet.quizletandroid.interactor.t) r8
            kotlinx.coroutines.flow.i r8 = r8.a(r4)
            long r5 = com.quizlet.quizletandroid.initializers.app.k.a
            r1.j = r7
            r1.m = r4
            int r3 = com.quizlet.qutils.coroutines.c.a
            com.quizlet.qutils.coroutines.b r3 = new com.quizlet.qutils.coroutines.b
            r4 = 0
            r3.<init>(r8, r4)
            long r4 = kotlinx.coroutines.E.H(r5)
            java.lang.Object r8 = kotlinx.coroutines.E.L(r4, r3, r1)
            if (r8 != r2) goto L61
            r0.stop()
            return r2
        L61:
            r1 = r7
        L62:
            com.quizlet.data.model.i0 r8 = (com.quizlet.data.model.C4135i0) r8
            java.lang.Object r1 = r1.b
            com.quizlet.usecase.b r1 = (com.quizlet.usecase.b) r1
            com.quizlet.usecase.a r1 = (com.quizlet.usecase.a) r1
            r1.a(r8)
            kotlin.Unit r8 = kotlin.Unit.a
            r0.stop()
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.login.a.h(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:36:0x00b0  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x00b8  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object i(java.lang.String r9, kotlin.coroutines.jvm.internal.c r10, boolean r11) throws com.quizlet.data.exceptions.notes.NotesException {
        /*
            Method dump skipped, instructions count: 270
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.login.a.i(java.lang.String, kotlin.coroutines.jvm.internal.c, boolean):java.lang.Object");
    }

    public p j(c userProps) {
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        return L1.e((AbstractC5040y) this.a, new com.quizlet.featuregate.features.region.c(this, userProps, null));
    }

    public void k(List modules, boolean z) throws DefinitionOverrideException {
        Intrinsics.checkNotNullParameter(modules, "modules");
        Intrinsics.checkNotNullParameter(modules, "modules");
        LinkedHashSet<org.koin.core.module.a> modules2 = new LinkedHashSet();
        AbstractC3406w2.b(modules2, modules);
        com.quizlet.data.repository.user.a aVar = (com.quizlet.data.repository.user.a) this.b;
        aVar.getClass();
        Intrinsics.checkNotNullParameter(modules2, "modules");
        for (org.koin.core.module.a aVar2 : modules2) {
            for (Map.Entry entry : aVar2.c.entrySet()) {
                String mapping = (String) entry.getKey();
                org.koin.core.instance.b factory = (org.koin.core.instance.b) entry.getValue();
                Intrinsics.checkNotNullParameter(mapping, "mapping");
                Intrinsics.checkNotNullParameter(factory, "factory");
                ConcurrentHashMap concurrentHashMap = (ConcurrentHashMap) aVar.c;
                boolean zContainsKey = concurrentHashMap.containsKey(mapping);
                a aVar3 = (a) aVar.b;
                if (zContainsKey) {
                    if (!z) {
                        Intrinsics.checkNotNullParameter(factory, "factory");
                        Intrinsics.checkNotNullParameter(mapping, "mapping");
                        String msg = "Already existing definition for " + factory.a + " at " + mapping;
                        Intrinsics.checkNotNullParameter(msg, "msg");
                        throw new DefinitionOverrideException(msg);
                    }
                    com.quizlet.quizletandroid.ui.joincontenttofolder.j jVar = (com.quizlet.quizletandroid.ui.joincontenttofolder.j) aVar3.c;
                    StringBuilder sbY = android.support.v4.media.session.a.y("(+) override index '", mapping, "' -> '");
                    sbY.append(factory.a);
                    sbY.append('\'');
                    String msg2 = sbY.toString();
                    jVar.getClass();
                    Intrinsics.checkNotNullParameter(msg2, "msg");
                    jVar.g(org.koin.core.logger.a.c, msg2);
                }
                com.quizlet.quizletandroid.ui.joincontenttofolder.j jVar2 = (com.quizlet.quizletandroid.ui.joincontenttofolder.j) aVar3.c;
                StringBuilder sbY2 = android.support.v4.media.session.a.y("(+) index '", mapping, "' -> '");
                sbY2.append(factory.a);
                sbY2.append('\'');
                jVar2.a(sbY2.toString());
                concurrentHashMap.put(mapping, factory);
            }
            Iterator it2 = aVar2.b.iterator();
            while (it2.hasNext()) {
                org.koin.core.instance.c cVar = (org.koin.core.instance.c) it2.next();
                ((HashMap) aVar.d).put(Integer.valueOf(cVar.a.hashCode()), cVar);
            }
        }
        org.koin.core.registry.a aVar4 = (org.koin.core.registry.a) this.a;
        aVar4.getClass();
        Intrinsics.checkNotNullParameter(modules2, "modules");
        Iterator it3 = modules2.iterator();
        while (it3.hasNext()) {
            aVar4.a.addAll(((org.koin.core.module.a) it3.next()).d);
        }
    }

    public void l(A a) {
        androidx.camera.camera2.internal.A a2 = (androidx.camera.camera2.internal.A) this.c;
        if (a2 != null) {
            a2.run();
        }
        androidx.camera.camera2.internal.A a3 = new androidx.camera.camera2.internal.A((L) this.a, a);
        this.c = a3;
        ((Handler) this.b).postAtFrontOfQueue(a3);
    }

    /* JADX WARN: Code restructure failed: missing block: B:35:0x00c5, code lost:
    
        if (r12.o(r10, r0) == r1) goto L36;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.io.Serializable m(java.util.List r10, boolean r11, kotlin.coroutines.jvm.internal.c r12) {
        /*
            Method dump skipped, instructions count: 236
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.login.a.m(java.util.List, boolean, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    public byte[] n(C3618f5 c3618f5) {
        C3684o c3684o;
        com.google.firebase.encoders.c cVar;
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try {
            HashMap map = (HashMap) this.a;
            c3684o = new C3684o(byteArrayOutputStream, map, (HashMap) this.b, (C3676n) this.c);
            cVar = (com.google.firebase.encoders.c) map.get(C3618f5.class);
        } catch (IOException unused) {
        }
        if (cVar == null) {
            throw new EncodingException("No encoder for ".concat(String.valueOf(C3618f5.class)));
        }
        cVar.a(c3618f5, c3684o);
        return byteArrayOutputStream.toByteArray();
    }

    public a(t loggedInUserInteractor, com.quizlet.usecase.b userUseCase) {
        Intrinsics.checkNotNullParameter(loggedInUserInteractor, "loggedInUserInteractor");
        Intrinsics.checkNotNullParameter(userUseCase, "userUseCase");
        this.a = loggedInUserInteractor;
        this.b = userUseCase;
        this.c = new J0(loggedInUserInteractor.a(false), new com.quizlet.quizletandroid.initializers.app.j(this, null), 5);
    }

    public a(com.quizlet.quizletandroid.deeplinks.a explanationsDeepLinkLookup, com.quizlet.quizletandroid.deeplinks.a setPageDeepLinkLookup, com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager) {
        Intrinsics.checkNotNullParameter(explanationsDeepLinkLookup, "explanationsDeepLinkLookup");
        Intrinsics.checkNotNullParameter(setPageDeepLinkLookup, "setPageDeepLinkLookup");
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        this.a = explanationsDeepLinkLookup;
        this.b = setPageDeepLinkLookup;
        this.c = loggedInUserManager;
    }

    public a(AbstractC5040y dispatcher, H h, int i) {
        Object countryCodes;
        com.quizlet.featuregate.features.region.a countryCodeType = com.quizlet.featuregate.features.region.a.b;
        if (h != null) {
            countryCodes = kotlin.collections.A.b(h);
        } else {
            countryCodes = K.a;
        }
        countryCodeType = (i & 8) != 0 ? com.quizlet.featuregate.features.region.a.a : countryCodeType;
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        Intrinsics.checkNotNullParameter(countryCodes, "countryCodes");
        Intrinsics.checkNotNullParameter(countryCodeType, "countryCodeType");
        this.a = dispatcher;
        this.b = countryCodes;
        this.c = countryCodeType;
    }

    public a(int i) {
        switch (i) {
            case 19:
                this.a = new org.koin.core.registry.a(this);
                this.b = new com.quizlet.data.repository.user.a(this);
                Intrinsics.checkNotNullParameter(this, "_koin");
                new ConcurrentHashMap();
                Intrinsics.checkNotNullParameter(this, "_koin");
                new HashMap();
                org.koin.core.logger.a level = org.koin.core.logger.a.e;
                Intrinsics.checkNotNullParameter(level, "level");
                this.c = new com.quizlet.quizletandroid.ui.joincontenttofolder.j(6);
                break;
            default:
                this.a = new androidx.compose.ui.text.caches.b(16);
                androidx.compose.ui.text.caches.c cVar = new androidx.compose.ui.text.caches.c();
                cVar.a = androidx.compose.ui.text.caches.a.a;
                cVar.b = androidx.compose.ui.text.caches.a.b;
                cVar.c = 0;
                this.b = cVar;
                this.c = new u(3);
                break;
        }
    }
}
