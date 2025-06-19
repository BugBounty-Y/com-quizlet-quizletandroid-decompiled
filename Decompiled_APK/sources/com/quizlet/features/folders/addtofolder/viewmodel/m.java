package com.quizlet.features.folders.addtofolder.viewmodel;

import androidx.compose.foundation.gestures.l1;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import androidx.navigation.U;
import androidx.paging.J0;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3097a5;
import com.google.firebase.messaging.p;
import com.google.firebase.sessions.H;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.features.folders.addtofolder.data.o;
import com.quizlet.features.folders.addtofolder.data.q;
import com.quizlet.features.folders.addtofolder.data.r;
import com.quizlet.features.folders.addtofolder.data.s;
import com.quizlet.features.folders.addtofolder.data.t;
import com.quizlet.features.folders.addtofolder.data.u;
import com.quizlet.generated.enums.y1;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class m extends w0 implements n {
    public final com.google.firebase.crashlytics.internal.settings.b b;
    public final l1 c;
    public final p d;
    public final l1 e;
    public final C1608n f;
    public final com.quizlet.features.folders.logging.e g;
    public final com.quizlet.data.repository.user.a h;
    public final io.ktor.client.plugins.api.d i;
    public final s0 j;
    public final d0 k;
    public ArrayList l;
    public List m;
    public Long n;
    public String o;
    public t p;

    public m(com.google.firebase.crashlytics.internal.settings.b checkNotesEligibilityUseCase, l1 getAllStudySetsCardWithCreatorUseCase, p getMyExplanationsVMUseCase, l1 getAllStudyNotesVMUseCase, C1608n getFolderMenuItemsVMUseCase, com.quizlet.features.folders.logging.e folderEventLogger, com.quizlet.data.repository.user.a subFolderFeature, io.ktor.client.plugins.api.d getFolderRecommendationsVMUseCase) {
        Intrinsics.checkNotNullParameter(checkNotesEligibilityUseCase, "checkNotesEligibilityUseCase");
        Intrinsics.checkNotNullParameter(getAllStudySetsCardWithCreatorUseCase, "getAllStudySetsCardWithCreatorUseCase");
        Intrinsics.checkNotNullParameter(getMyExplanationsVMUseCase, "getMyExplanationsVMUseCase");
        Intrinsics.checkNotNullParameter(getAllStudyNotesVMUseCase, "getAllStudyNotesVMUseCase");
        Intrinsics.checkNotNullParameter(getFolderMenuItemsVMUseCase, "getFolderMenuItemsVMUseCase");
        Intrinsics.checkNotNullParameter(folderEventLogger, "folderEventLogger");
        Intrinsics.checkNotNullParameter(subFolderFeature, "subFolderFeature");
        Intrinsics.checkNotNullParameter(getFolderRecommendationsVMUseCase, "getFolderRecommendationsVMUseCase");
        this.b = checkNotesEligibilityUseCase;
        this.c = getAllStudySetsCardWithCreatorUseCase;
        this.d = getMyExplanationsVMUseCase;
        this.e = getAllStudyNotesVMUseCase;
        this.f = getFolderMenuItemsVMUseCase;
        this.g = folderEventLogger;
        this.h = subFolderFeature;
        this.i = getFolderRecommendationsVMUseCase;
        o oVar = o.a;
        K k = K.a;
        q qVar = q.a;
        this.j = e0.c(new u(u.o, oVar, k, qVar, qVar, qVar, qVar, false, false, null, 0, k, 0, 0));
        this.k = e0.b(0, 1, null, 5);
        this.l = new ArrayList();
        this.m = kotlinx.collections.immutable.implementations.immutableList.g.c;
        E.A(p0.j(this), null, null, new b(this, null), 3);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x001a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object A(com.quizlet.features.folders.addtofolder.viewmodel.m r17, kotlin.coroutines.jvm.internal.c r18) {
        /*
            r0 = r17
            r1 = r18
            r0.getClass()
            boolean r2 = r1 instanceof com.quizlet.features.folders.addtofolder.viewmodel.d
            if (r2 == 0) goto L1a
            r2 = r1
            com.quizlet.features.folders.addtofolder.viewmodel.d r2 = (com.quizlet.features.folders.addtofolder.viewmodel.d) r2
            int r3 = r2.m
            r4 = -2147483648(0xffffffff80000000, float:-0.0)
            r5 = r3 & r4
            if (r5 == 0) goto L1a
            int r3 = r3 - r4
            r2.m = r3
            goto L1f
        L1a:
            com.quizlet.features.folders.addtofolder.viewmodel.d r2 = new com.quizlet.features.folders.addtofolder.viewmodel.d
            r2.<init>(r0, r1)
        L1f:
            java.lang.Object r1 = r2.k
            kotlin.coroutines.intrinsics.a r3 = kotlin.coroutines.intrinsics.a.a
            int r4 = r2.m
            r5 = 1
            if (r4 == 0) goto L38
            if (r4 != r5) goto L30
            com.quizlet.features.folders.addtofolder.viewmodel.m r0 = r2.j
            androidx.glance.appwidget.protobuf.Z.e(r1)
            goto L48
        L30:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r1 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r1)
            throw r0
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r1)
            r2.j = r0
            r2.m = r5
            com.google.firebase.crashlytics.internal.settings.b r1 = r0.b
            java.lang.Object r1 = r1.h(r2)
            if (r1 != r3) goto L48
            return r3
        L48:
            java.lang.Boolean r1 = (java.lang.Boolean) r1
            boolean r1 = r1.booleanValue()
            if (r1 == 0) goto L73
            kotlinx.coroutines.flow.s0 r0 = r0.j
        L52:
            java.lang.Object r1 = r0.getValue()
            r2 = r1
            com.quizlet.features.folders.addtofolder.data.u r2 = (com.quizlet.features.folders.addtofolder.data.u) r2
            java.util.List r3 = com.quizlet.features.folders.addtofolder.data.u.p
            r13 = 0
            r16 = 16382(0x3ffe, float:2.2956E-41)
            r4 = 0
            r5 = 0
            r6 = 0
            r7 = 0
            r8 = 0
            r9 = 0
            r10 = 0
            r11 = 0
            r12 = 0
            r14 = 0
            r15 = 0
            com.quizlet.features.folders.addtofolder.data.u r2 = com.quizlet.features.folders.addtofolder.data.u.a(r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16)
            boolean r1 = r0.k(r1, r2)
            if (r1 == 0) goto L52
        L73:
            kotlin.Unit r0 = kotlin.Unit.a
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.folders.addtofolder.viewmodel.m.A(com.quizlet.features.folders.addtofolder.viewmodel.m, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0017  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object B(com.quizlet.features.folders.addtofolder.viewmodel.m r17, long r18, kotlin.coroutines.jvm.internal.c r20) {
        /*
            r0 = r17
            r1 = r20
            boolean r2 = r1 instanceof com.quizlet.features.folders.addtofolder.viewmodel.e
            if (r2 == 0) goto L17
            r2 = r1
            com.quizlet.features.folders.addtofolder.viewmodel.e r2 = (com.quizlet.features.folders.addtofolder.viewmodel.e) r2
            int r3 = r2.m
            r4 = -2147483648(0xffffffff80000000, float:-0.0)
            r5 = r3 & r4
            if (r5 == 0) goto L17
            int r3 = r3 - r4
            r2.m = r3
            goto L1c
        L17:
            com.quizlet.features.folders.addtofolder.viewmodel.e r2 = new com.quizlet.features.folders.addtofolder.viewmodel.e
            r2.<init>(r0, r1)
        L1c:
            java.lang.Object r1 = r2.k
            kotlin.coroutines.intrinsics.a r3 = kotlin.coroutines.intrinsics.a.a
            int r4 = r2.m
            r5 = 1
            if (r4 == 0) goto L35
            if (r4 != r5) goto L2d
            com.quizlet.features.folders.addtofolder.viewmodel.m r0 = r2.j
            androidx.glance.appwidget.protobuf.Z.e(r1)
            goto L47
        L2d:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r1 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r1)
            throw r0
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r1)
            r2.j = r0
            r2.m = r5
            com.google.android.gms.ads.internal.client.n r1 = r0.f
            r4 = r18
            java.io.Serializable r1 = r1.t(r4, r2)
            if (r1 != r3) goto L47
            return r3
        L47:
            r5 = r1
            java.util.List r5 = (java.util.List) r5
            kotlinx.coroutines.flow.s0 r0 = r0.j
        L4c:
            java.lang.Object r1 = r0.getValue()
            r2 = r1
            com.quizlet.features.folders.addtofolder.data.u r2 = (com.quizlet.features.folders.addtofolder.data.u) r2
            r13 = 0
            r16 = 16379(0x3ffb, float:2.2952E-41)
            r3 = 0
            r4 = 0
            r6 = 0
            r7 = 0
            r8 = 0
            r9 = 0
            r10 = 0
            r11 = 0
            r12 = 0
            r14 = 0
            r15 = 0
            com.quizlet.features.folders.addtofolder.data.u r2 = com.quizlet.features.folders.addtofolder.data.u.a(r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16)
            boolean r1 = r0.k(r1, r2)
            if (r1 == 0) goto L4c
            kotlin.Unit r0 = kotlin.Unit.a
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.folders.addtofolder.viewmodel.m.B(com.quizlet.features.folders.addtofolder.viewmodel.m, long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final Object C(m mVar, o oVar, kotlin.coroutines.jvm.internal.i iVar) {
        s0 s0Var;
        Object value;
        int iOrdinal = oVar.ordinal();
        if (iOrdinal != 0) {
            if (iOrdinal == 1) {
                Object objH = mVar.H(iVar);
                return objH == kotlin.coroutines.intrinsics.a.a ? objH : Unit.a;
            }
            if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            Object objF = mVar.F(iVar);
            return objF == kotlin.coroutines.intrinsics.a.a ? objF : Unit.a;
        }
        do {
            s0Var = mVar.j;
            value = s0Var.getValue();
        } while (!s0Var.k(value, u.a((u) value, null, null, null, q.a, null, null, null, false, null, 0, null, 0, 0, 16375)));
        ArrayList arrayList = mVar.l;
        ArrayList selectedStudyMaterials = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            if (next instanceof com.quizlet.ui.models.content.listitem.l) {
                selectedStudyMaterials.add(next);
            }
        }
        l1 l1Var = mVar.c;
        l1Var.getClass();
        Intrinsics.checkNotNullParameter(selectedStudyMaterials, "selectedStudyMaterials");
        Object objI = e0.i(new com.quizlet.features.folders.addtofolder.viewmodel.usecase.c(new J0(((com.quizlet.quizletandroid.interactor.m) l1Var.c).b(), new H(3, 1, null)), l1Var, selectedStudyMaterials, 0), new g(mVar, null), iVar);
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        if (objI != aVar) {
            objI = Unit.a;
        }
        return objI == aVar ? objI : Unit.a;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0017  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object D(com.quizlet.features.folders.addtofolder.viewmodel.m r21, kotlin.coroutines.jvm.internal.c r22) {
        /*
            r0 = r21
            r1 = r22
            boolean r2 = r1 instanceof com.quizlet.features.folders.addtofolder.viewmodel.j
            if (r2 == 0) goto L17
            r2 = r1
            com.quizlet.features.folders.addtofolder.viewmodel.j r2 = (com.quizlet.features.folders.addtofolder.viewmodel.j) r2
            int r3 = r2.m
            r4 = -2147483648(0xffffffff80000000, float:-0.0)
            r5 = r3 & r4
            if (r5 == 0) goto L17
            int r3 = r3 - r4
            r2.m = r3
            goto L1c
        L17:
            com.quizlet.features.folders.addtofolder.viewmodel.j r2 = new com.quizlet.features.folders.addtofolder.viewmodel.j
            r2.<init>(r0, r1)
        L1c:
            java.lang.Object r1 = r2.k
            kotlin.coroutines.intrinsics.a r3 = kotlin.coroutines.intrinsics.a.a
            int r4 = r2.m
            r5 = 1
            if (r4 == 0) goto L35
            if (r4 != r5) goto L2d
            com.quizlet.features.folders.addtofolder.viewmodel.m r0 = r2.j
            androidx.glance.appwidget.protobuf.Z.e(r1)
            goto L43
        L2d:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r1 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r1)
            throw r0
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r1)
            r2.j = r0
            r2.m = r5
            java.lang.Object r1 = r0.G(r2)
            if (r1 != r3) goto L43
            return r3
        L43:
            java.util.List r1 = (java.util.List) r1
            kotlinx.coroutines.flow.s0 r2 = r0.j
        L47:
            java.lang.Object r3 = r2.getValue()
            r6 = r3
            com.quizlet.features.folders.addtofolder.data.u r6 = (com.quizlet.features.folders.addtofolder.data.u) r6
            java.util.ArrayList r4 = new java.util.ArrayList
            r4.<init>()
            com.quizlet.features.folders.addtofolder.data.t r7 = com.quizlet.features.folders.addtofolder.data.t.b
            r4.add(r7)
            r0.p = r7
            if (r1 == 0) goto L68
            boolean r7 = r1.isEmpty()
            r7 = r7 ^ r5
            if (r7 != r5) goto L68
            com.quizlet.features.folders.addtofolder.data.t r7 = com.quizlet.features.folders.addtofolder.data.t.a
            r4.add(r7)
        L68:
            com.quizlet.features.folders.addtofolder.data.p r13 = new com.quizlet.features.folders.addtofolder.data.p
            if (r1 != 0) goto L6f
            kotlin.collections.K r7 = kotlin.collections.K.a
            goto L70
        L6f:
            r7 = r1
        L70:
            r13.<init>(r7)
            r16 = 0
            r20 = 13119(0x333f, float:1.8384E-41)
            r7 = 0
            r8 = 0
            r9 = 0
            r10 = 0
            r11 = 0
            r12 = 0
            r14 = 0
            r15 = 0
            r18 = 0
            r19 = 0
            r17 = r4
            com.quizlet.features.folders.addtofolder.data.u r4 = com.quizlet.features.folders.addtofolder.data.u.a(r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18, r19, r20)
            boolean r3 = r2.k(r3, r4)
            if (r3 == 0) goto L47
            kotlin.Unit r0 = kotlin.Unit.a
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.folders.addtofolder.viewmodel.m.D(com.quizlet.features.folders.addtofolder.viewmodel.m, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static ArrayList E(List list, s sVar) {
        ArrayList arrayListY0 = CollectionsKt.y0(list);
        Iterator it2 = arrayListY0.iterator();
        int i = 0;
        while (true) {
            if (!it2.hasNext()) {
                i = -1;
                break;
            }
            s sVar2 = (s) it2.next();
            if (Intrinsics.b(sVar2.a.d(), sVar.a.d()) && sVar2.a.b() == sVar.a.b()) {
                break;
            }
            i++;
        }
        s sVar3 = (s) arrayListY0.get(i);
        boolean z = !sVar.b;
        com.quizlet.ui.models.content.listitem.o studyMaterial = sVar3.a;
        Intrinsics.checkNotNullParameter(studyMaterial, "studyMaterial");
        arrayListY0.set(i, new s(studyMaterial, z));
        return arrayListY0;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0017  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object F(kotlin.coroutines.jvm.internal.c r23) {
        /*
            Method dump skipped, instructions count: 214
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.folders.addtofolder.viewmodel.m.F(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object G(kotlin.coroutines.jvm.internal.c r10) {
        /*
            Method dump skipped, instructions count: 227
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.folders.addtofolder.viewmodel.m.G(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0017  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object H(kotlin.coroutines.jvm.internal.c r23) {
        /*
            Method dump skipped, instructions count: 202
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.folders.addtofolder.viewmodel.m.H(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final void I(com.quizlet.features.folders.addtofolder.data.n event) {
        Object value;
        Object value2;
        u uVar;
        Object value3;
        Object value4;
        Object value5;
        Object value6;
        Object value7;
        Object value8;
        Intrinsics.checkNotNullParameter(event, "event");
        boolean z = event instanceof com.quizlet.features.folders.addtofolder.data.a;
        s0 s0Var = this.j;
        if (z) {
            do {
                value8 = s0Var.getValue();
            } while (!s0Var.k(value8, u.a((u) value8, null, ((com.quizlet.features.folders.addtofolder.data.a) event).a, null, null, null, null, null, false, null, 0, null, 0, 0, 16381)));
            E.A(p0.j(this), null, null, new k(this, event, null), 3);
            return;
        }
        boolean zB = Intrinsics.b(event, com.quizlet.features.folders.addtofolder.data.d.a);
        com.quizlet.features.folders.logging.e eVar = this.g;
        if (zB) {
            Long l = this.n;
            String str = this.o;
            eVar.getClass();
            EventLoggerExt.a(eVar.a, "folder_add_new_confirm_click", new com.quizlet.features.folders.logging.a(l, str, 1));
            this.k.h(this.l);
            return;
        }
        if (Intrinsics.b(event, com.quizlet.features.folders.addtofolder.data.b.a)) {
            Long l2 = this.n;
            String str2 = this.o;
            eVar.getClass();
            EventLoggerExt.a(eVar.a, "folder_add_new_dismiss_click", new com.quizlet.features.folders.logging.a(l2, str2, 0));
            return;
        }
        if (event instanceof com.quizlet.features.folders.addtofolder.data.e) {
            com.quizlet.features.folders.addtofolder.data.e eVar2 = (com.quizlet.features.folders.addtofolder.data.e) event;
            this.l = CollectionsKt.y0(eVar2.a);
            this.m = AbstractC3097a5.c(eVar2.a);
            this.n = Long.valueOf(eVar2.c);
            String str3 = eVar2.d;
            this.o = str3;
            E.A(p0.j(this), null, null, new l(this, event, null), 3);
            if (eVar2.e) {
                eVar.getClass();
                com.quizlet.features.folders.logging.e.b(eVar, eVar2.c, "add_material_to_folder_viewed", null, null, null, "add_items_to_folder", new androidx.navigation.internal.h(str3, 17), 56);
            }
            do {
                value7 = s0Var.getValue();
            } while (!s0Var.k(value7, u.a((u) value7, null, null, null, null, null, null, null, false, null, 0, null, 0, 0, 4095)));
            return;
        }
        if (!(event instanceof com.quizlet.features.folders.addtofolder.data.l)) {
            if (Intrinsics.b(event, com.quizlet.features.folders.addtofolder.data.c.a)) {
                Long l3 = this.n;
                String str4 = this.o;
                eVar.getClass();
                EventLoggerExt.a(eVar.a, "folder_add_new_modal_create_new_clicked", new com.quizlet.features.folders.logging.a(l3, str4, 2));
                return;
            }
            if (event instanceof com.quizlet.features.folders.addtofolder.data.f) {
                com.quizlet.features.folders.addtofolder.data.f fVar = (com.quizlet.features.folders.addtofolder.data.f) event;
                Long l4 = this.n;
                eVar.d(new com.quizlet.features.folders.logging.f(l4 != null ? l4.longValue() : 0L, fVar.a.d(), fVar.a.b(), false, Integer.valueOf(fVar.b), this.o, 24));
                return;
            }
            if (event instanceof com.quizlet.features.folders.addtofolder.data.m) {
                com.quizlet.features.folders.addtofolder.data.m mVar = (com.quizlet.features.folders.addtofolder.data.m) event;
                this.p = mVar.a;
                do {
                    value2 = s0Var.getValue();
                    uVar = (u) value2;
                } while (!s0Var.k(value2, u.a(uVar, null, null, null, null, null, null, null, false, null, uVar.l.indexOf(mVar.a), null, 0, 0, 15359)));
                return;
            }
            if (Intrinsics.b(event, com.quizlet.features.folders.addtofolder.data.i.a)) {
                K(true);
                return;
            }
            if (Intrinsics.b(event, com.quizlet.features.folders.addtofolder.data.h.a)) {
                K(false);
                return;
            }
            if (Intrinsics.b(event, com.quizlet.features.folders.addtofolder.data.j.a)) {
                J();
                return;
            }
            if (event instanceof com.quizlet.features.folders.addtofolder.data.k) {
                String str5 = ((com.quizlet.features.folders.addtofolder.data.k) event).a;
                do {
                    value = s0Var.getValue();
                } while (!s0Var.k(value, u.a((u) value, null, null, null, null, null, null, null, false, str5, 0, null, 0, 0, 15871)));
                return;
            } else {
                if (!Intrinsics.b(event, com.quizlet.features.folders.addtofolder.data.g.a)) {
                    throw new NoWhenBranchMatchedException();
                }
                K(false);
                return;
            }
        }
        com.quizlet.features.folders.addtofolder.data.l lVar = (com.quizlet.features.folders.addtofolder.data.l) event;
        s sVar = lVar.a;
        if (!this.l.removeIf(new a(0, new U(sVar, 29)))) {
            this.l.add(sVar.a);
        }
        int size = CollectionsKt.b0(AbstractC3097a5.c(this.l), CollectionsKt.A0(this.m)).size();
        int size2 = CollectionsKt.b0(this.m, CollectionsKt.A0(AbstractC3097a5.c(this.l))).size();
        com.quizlet.ui.models.content.listitem.o oVar = sVar.a;
        String strD = oVar.d();
        y1 y1VarB = oVar.b();
        Long l5 = this.n;
        long jLongValue = l5 != null ? l5.longValue() : 0L;
        com.quizlet.features.folders.logging.f loggingMaterialData = new com.quizlet.features.folders.logging.f(jLongValue, strD, y1VarB, false, Integer.valueOf(lVar.b), this.o, 152);
        eVar.c(loggingMaterialData);
        if (sVar.b) {
            String str6 = this.o;
            Intrinsics.checkNotNullParameter(loggingMaterialData, "loggingMaterialData");
            com.quizlet.features.folders.logging.e.b(eVar, jLongValue, "folder_item_removed", "add_material_to_folder", strD, y1VarB, "add_items_to_folder", new androidx.navigation.internal.h(str6, 20), 4);
        } else {
            String str7 = this.o;
            Intrinsics.checkNotNullParameter(loggingMaterialData, "loggingMaterialData");
            com.quizlet.features.folders.logging.e.b(eVar, jLongValue, "added_to_existing_folder", "add_material_to_folder", strD, y1VarB, "add_items_to_folder", new androidx.navigation.internal.h(str7, 19), 4);
        }
        t tVar = this.p;
        int i = tVar == null ? -1 : c.a[tVar.ordinal()];
        if (i != -1) {
            if (i == 1) {
                r rVar = ((u) s0Var.getValue()).g;
                Intrinsics.e(rVar, "null cannot be cast to non-null type com.quizlet.features.folders.addtofolder.data.AddToFolderListState.Content");
                ArrayList arrayListE = E(((com.quizlet.features.folders.addtofolder.data.p) rVar).a, sVar);
                do {
                    value6 = s0Var.getValue();
                } while (!s0Var.k(value6, u.a((u) value6, null, null, null, null, null, null, new com.quizlet.features.folders.addtofolder.data.p(arrayListE), false, null, 0, null, size, size2, 4031)));
                return;
            }
            if (i != 2) {
                throw new NoWhenBranchMatchedException();
            }
        }
        int i2 = c.b[sVar.a.b().ordinal()];
        if (i2 == 1) {
            r rVar2 = ((u) s0Var.getValue()).d;
            Intrinsics.e(rVar2, "null cannot be cast to non-null type com.quizlet.features.folders.addtofolder.data.AddToFolderListState.Content");
            ArrayList arrayListE2 = E(((com.quizlet.features.folders.addtofolder.data.p) rVar2).a, sVar);
            do {
                value3 = s0Var.getValue();
            } while (!s0Var.k(value3, u.a((u) value3, null, null, null, new com.quizlet.features.folders.addtofolder.data.p(arrayListE2), null, null, null, false, null, 0, null, size, size2, 4087)));
            return;
        }
        if (i2 == 2 || i2 == 3 || i2 == 4) {
            r rVar3 = ((u) s0Var.getValue()).f;
            Intrinsics.e(rVar3, "null cannot be cast to non-null type com.quizlet.features.folders.addtofolder.data.AddToFolderListState.Content");
            ArrayList arrayListE3 = E(((com.quizlet.features.folders.addtofolder.data.p) rVar3).a, sVar);
            do {
                value4 = s0Var.getValue();
            } while (!s0Var.k(value4, u.a((u) value4, null, null, null, null, null, new com.quizlet.features.folders.addtofolder.data.p(arrayListE3), null, false, null, 0, null, size, size2, 4063)));
            return;
        }
        if (i2 != 5) {
            throw new IllegalArgumentException("Unknown study material type");
        }
        r rVar4 = ((u) s0Var.getValue()).e;
        Intrinsics.e(rVar4, "null cannot be cast to non-null type com.quizlet.features.folders.addtofolder.data.AddToFolderListState.Content");
        ArrayList arrayListE4 = E(((com.quizlet.features.folders.addtofolder.data.p) rVar4).a, sVar);
        do {
            value5 = s0Var.getValue();
        } while (!s0Var.k(value5, u.a((u) value5, null, null, null, null, new com.quizlet.features.folders.addtofolder.data.p(arrayListE4), null, null, false, null, 0, null, size, size2, 4079)));
    }

    public final void J() {
        s0 s0Var;
        Object value;
        do {
            s0Var = this.j;
            value = s0Var.getValue();
        } while (!s0Var.k(value, u.a((u) value, null, null, null, null, null, null, null, false, null, 0, null, 0, 0, 15871)));
    }

    public final void K(boolean z) {
        s0 s0Var;
        Object value;
        do {
            s0Var = this.j;
            value = s0Var.getValue();
        } while (!s0Var.k(value, u.a((u) value, null, null, null, null, null, null, null, z, null, 0, null, 0, 0, 16127)));
        J();
    }
}
