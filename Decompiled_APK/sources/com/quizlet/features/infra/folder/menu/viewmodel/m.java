package com.quizlet.features.infra.folder.menu.viewmodel;

import androidx.compose.material.ripple.r;
import androidx.navigation.compose.C1279l;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.quizlet.data.model.C4169u;
import com.quizlet.data.model.EnumC4159q0;
import com.quizlet.edgy.ui.viewmodel.C4203d;
import com.quizlet.eventlogger.features.folder.FolderLogger;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import com.quizlet.generated.enums.y1;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.q0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class m implements n {
    public final r a;
    public final FolderLogger b;
    public final AbstractC5040y c;
    public final com.quizlet.data.repository.user.a d;
    public final kotlinx.coroutines.internal.d e;
    public final C4203d f;
    public final s0 g;
    public final d0 h;
    public final d0 i;
    public final d0 j;
    public final s0 k;
    public y1 l;
    public String m;

    public m(r addToFolderPresenterUseCase, com.quizlet.data.repository.explanations.myexplanations.a validateFolderTagUseCase, FolderLogger folderEventLogger, AbstractC5040y ioDispatcher, com.quizlet.data.repository.user.a subfolderFeature) {
        Intrinsics.checkNotNullParameter(addToFolderPresenterUseCase, "addToFolderPresenterUseCase");
        Intrinsics.checkNotNullParameter(validateFolderTagUseCase, "validateFolderTagUseCase");
        Intrinsics.checkNotNullParameter(folderEventLogger, "folderEventLogger");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        Intrinsics.checkNotNullParameter(subfolderFeature, "subfolderFeature");
        this.a = addToFolderPresenterUseCase;
        this.b = folderEventLogger;
        this.c = ioDispatcher;
        this.d = subfolderFeature;
        kotlinx.coroutines.internal.d dVarC = E.c(ioDispatcher);
        this.e = dVarC;
        this.f = new C4203d(this);
        this.g = e0.c(com.quizlet.features.infra.folder.menu.screenstates.b.a);
        this.h = e0.b(0, 1, null, 5);
        this.i = e0.b(0, 1, null, 5);
        this.j = e0.b(0, 1, null, 5);
        this.k = e0.c(Boolean.FALSE);
        E.A(dVarC, null, null, new c(this, null), 3);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(com.quizlet.features.infra.folder.menu.viewmodel.m r4, java.lang.String r5, com.quizlet.data.interactor.folderstudymaterial.g r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4.getClass()
            boolean r0 = r7 instanceof com.quizlet.features.infra.folder.menu.viewmodel.e
            if (r0 == 0) goto L16
            r0 = r7
            com.quizlet.features.infra.folder.menu.viewmodel.e r0 = (com.quizlet.features.infra.folder.menu.viewmodel.e) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.o = r1
            goto L1b
        L16:
            com.quizlet.features.infra.folder.menu.viewmodel.e r0 = new com.quizlet.features.infra.folder.menu.viewmodel.e
            r0.<init>(r4, r7)
        L1b:
            java.lang.Object r7 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 1
            if (r2 == 0) goto L3c
            if (r2 != r3) goto L34
            com.quizlet.data.interactor.folderstudymaterial.g r6 = r0.l
            java.lang.String r5 = r0.k
            com.quizlet.features.infra.folder.menu.viewmodel.m r4 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlin.r r7 = (kotlin.r) r7
            java.lang.Object r7 = r7.a
            goto L50
        L34:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L3c:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.j = r4
            r0.k = r5
            r0.l = r6
            r0.o = r3
            androidx.compose.material.ripple.r r7 = r4.a
            java.lang.Object r7 = r7.i(r6, r0)
            if (r7 != r1) goto L50
            return r1
        L50:
            kotlin.p r0 = kotlin.r.b
            boolean r0 = r7 instanceof kotlin.q
            if (r0 != 0) goto L65
            r0 = r7
            com.quizlet.data.interactor.folderstudymaterial.h r0 = (com.quizlet.data.interactor.folderstudymaterial.h) r0
            kotlinx.coroutines.flow.d0 r1 = r4.h
            com.quizlet.features.infra.folder.menu.data.o r2 = new com.quizlet.features.infra.folder.menu.data.o
            com.quizlet.data.interactor.folderstudymaterial.g r0 = r0.a
            r2.<init>(r5, r0)
            r1.h(r2)
        L65:
            java.lang.Throwable r7 = kotlin.r.a(r7)
            if (r7 == 0) goto L99
            boolean r0 = r6 instanceof com.quizlet.data.interactor.folderstudymaterial.d
            if (r0 == 0) goto L75
            com.quizlet.features.infra.folder.menu.data.AddToFolderException$Adding r6 = new com.quizlet.features.infra.folder.menu.data.AddToFolderException$Adding
            r6.<init>(r7)
            goto L88
        L75:
            boolean r0 = r6 instanceof com.quizlet.data.interactor.folderstudymaterial.f
            if (r0 == 0) goto L7f
            com.quizlet.features.infra.folder.menu.data.AddToFolderException$Removing r6 = new com.quizlet.features.infra.folder.menu.data.AddToFolderException$Removing
            r6.<init>(r7)
            goto L88
        L7f:
            boolean r6 = r6 instanceof com.quizlet.data.interactor.folderstudymaterial.e
            if (r6 == 0) goto L93
            com.quizlet.features.infra.folder.menu.data.AddToFolderException$Multi r6 = new com.quizlet.features.infra.folder.menu.data.AddToFolderException$Multi
            r6.<init>(r7)
        L88:
            kotlinx.coroutines.flow.d0 r4 = r4.h
            com.quizlet.features.infra.folder.menu.data.m r7 = new com.quizlet.features.infra.folder.menu.data.m
            r7.<init>(r5, r6)
            r4.h(r7)
            goto L99
        L93:
            kotlin.NoWhenBranchMatchedException r4 = new kotlin.NoWhenBranchMatchedException
            r4.<init>()
            throw r4
        L99:
            kotlin.Unit r4 = kotlin.Unit.a
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.folder.menu.viewmodel.m.a(com.quizlet.features.infra.folder.menu.viewmodel.m, java.lang.String, com.quizlet.data.interactor.folderstudymaterial.g, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object d(com.quizlet.features.infra.folder.menu.viewmodel.m r5, java.lang.String r6, com.quizlet.generated.enums.y1 r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r5.getClass()
            boolean r0 = r8 instanceof com.quizlet.features.infra.folder.menu.viewmodel.f
            if (r0 == 0) goto L16
            r0 = r8
            com.quizlet.features.infra.folder.menu.viewmodel.f r0 = (com.quizlet.features.infra.folder.menu.viewmodel.f) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.m = r1
            goto L1b
        L16:
            com.quizlet.features.infra.folder.menu.viewmodel.f r0 = new com.quizlet.features.infra.folder.menu.viewmodel.f
            r0.<init>(r5, r8)
        L1b:
            java.lang.Object r8 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L38
            if (r2 != r3) goto L30
            com.quizlet.features.infra.folder.menu.viewmodel.m r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            kotlin.r r8 = (kotlin.r) r8
            java.lang.Object r6 = r8.a
            goto L48
        L30:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r0.j = r5
            r0.m = r3
            androidx.compose.material.ripple.r r8 = r5.a
            java.lang.Object r6 = r8.f(r6, r7, r0)
            if (r6 != r1) goto L48
            return r1
        L48:
            kotlin.p r7 = kotlin.r.b
            boolean r7 = r6 instanceof kotlin.q
            if (r7 != 0) goto Lac
            r7 = r6
            java.util.List r7 = (java.util.List) r7
            r5.getClass()
            boolean r8 = r7.isEmpty()
            if (r8 != 0) goto La5
            com.quizlet.features.infra.folder.menu.data.c r8 = com.quizlet.features.infra.folder.menu.data.c.a
            java.util.List r8 = kotlin.collections.A.b(r8)
            java.util.ArrayList r0 = new java.util.ArrayList
            r1 = 10
            int r1 = kotlin.collections.C.q(r7, r1)
            r0.<init>(r1)
            java.util.Iterator r7 = r7.iterator()
        L6f:
            boolean r1 = r7.hasNext()
            if (r1 == 0) goto L83
            java.lang.Object r1 = r7.next()
            com.quizlet.data.model.u r1 = (com.quizlet.data.model.C4169u) r1
            com.quizlet.features.infra.folder.menu.data.b r1 = r5.x(r1)
            r0.add(r1)
            goto L6f
        L83:
            java.util.ArrayList r7 = kotlin.collections.CollectionsKt.c0(r8, r0)
        L87:
            kotlinx.coroutines.flow.s0 r8 = r5.g
            java.lang.Object r0 = r8.getValue()
            r1 = r0
            com.quizlet.features.infra.folder.menu.screenstates.d r1 = (com.quizlet.features.infra.folder.menu.screenstates.d) r1
            com.quizlet.features.infra.folder.menu.screenstates.c r1 = new com.quizlet.features.infra.folder.menu.screenstates.c
            kotlinx.collections.immutable.e r2 = com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1.k(r7)
            kotlinx.collections.immutable.c r3 = t(r7)
            r4 = 0
            r1.<init>(r2, r3, r4)
            boolean r8 = r8.k(r0, r1)
            if (r8 == 0) goto L87
            goto Lac
        La5:
            kotlinx.coroutines.flow.d0 r7 = r5.i
            kotlin.Unit r8 = kotlin.Unit.a
            r7.h(r8)
        Lac:
            java.lang.Throwable r6 = kotlin.r.a(r6)
            if (r6 == 0) goto Lb5
            r5.w(r6)
        Lb5:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.folder.menu.viewmodel.m.d(com.quizlet.features.infra.folder.menu.viewmodel.m, java.lang.String, com.quizlet.generated.enums.y1, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object h(com.quizlet.features.infra.folder.menu.viewmodel.m r4, com.quizlet.data.interactor.folderstudymaterial.g r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4.getClass()
            boolean r0 = r6 instanceof com.quizlet.features.infra.folder.menu.viewmodel.l
            if (r0 == 0) goto L16
            r0 = r6
            com.quizlet.features.infra.folder.menu.viewmodel.l r0 = (com.quizlet.features.infra.folder.menu.viewmodel.l) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.m = r1
            goto L1b
        L16:
            com.quizlet.features.infra.folder.menu.viewmodel.l r0 = new com.quizlet.features.infra.folder.menu.viewmodel.l
            r0.<init>(r4, r6)
        L1b:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L38
            if (r2 != r3) goto L30
            com.quizlet.features.infra.folder.menu.viewmodel.m r4 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            kotlin.r r6 = (kotlin.r) r6
            java.lang.Object r5 = r6.a
            goto L48
        L30:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r4
            r0.m = r3
            androidx.compose.material.ripple.r r6 = r4.a
            java.lang.Object r5 = r6.i(r5, r0)
            if (r5 != r1) goto L48
            return r1
        L48:
            kotlin.p r6 = kotlin.r.b
            boolean r6 = r5 instanceof kotlin.q
            if (r6 != 0) goto L58
            r6 = r5
            com.quizlet.data.interactor.folderstudymaterial.h r6 = (com.quizlet.data.interactor.folderstudymaterial.h) r6
            kotlinx.coroutines.flow.d0 r6 = r4.h
            com.quizlet.features.infra.folder.menu.data.p r0 = com.quizlet.features.infra.folder.menu.data.p.a
            r6.h(r0)
        L58:
            java.lang.Throwable r5 = kotlin.r.a(r5)
            if (r5 == 0) goto L68
            kotlinx.coroutines.flow.d0 r4 = r4.h
            com.quizlet.features.infra.folder.menu.data.n r6 = new com.quizlet.features.infra.folder.menu.data.n
            r6.<init>(r5)
            r4.h(r6)
        L68:
            kotlin.Unit r4 = kotlin.Unit.a
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.folder.menu.viewmodel.m.h(com.quizlet.features.infra.folder.menu.viewmodel.m, com.quizlet.data.interactor.folderstudymaterial.g, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static kotlinx.collections.immutable.c t(List list) {
        List list2;
        LinkedHashSet linkedHashSet = new LinkedHashSet();
        ArrayList arrayList = new ArrayList();
        for (Object obj : list) {
            if (((com.quizlet.features.infra.folder.menu.data.g) obj).b()) {
                arrayList.add(obj);
            }
        }
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            com.quizlet.features.infra.folder.menu.data.g gVar = (com.quizlet.features.infra.folder.menu.data.g) it2.next();
            linkedHashSet.add(Long.valueOf(gVar.getId()));
            com.quizlet.features.infra.folder.menu.data.b bVar = gVar instanceof com.quizlet.features.infra.folder.menu.data.b ? (com.quizlet.features.infra.folder.menu.data.b) gVar : null;
            if (bVar != null && (list2 = bVar.d) != null) {
                ArrayList arrayList2 = new ArrayList();
                for (Object obj2 : list2) {
                    if (((com.quizlet.features.infra.folder.menu.data.f) obj2).b()) {
                        arrayList2.add(obj2);
                    }
                }
                Iterator it3 = arrayList2.iterator();
                while (it3.hasNext()) {
                    linkedHashSet.add(Long.valueOf(((com.quizlet.features.infra.folder.menu.data.f) it3.next()).getId()));
                }
            }
        }
        return AbstractC3409x1.j(linkedHashSet);
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final q0 b() {
        return this.k;
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void c(com.quizlet.features.infra.folder.menu.data.b option, boolean z) {
        Intrinsics.checkNotNullParameter(option, "option");
        if (z) {
            y(new C1279l(true, (Object) option, (Object) this, 3));
        }
        long j = option.a;
        String str = this.m;
        if (str == null) {
            Intrinsics.m("studyMaterialId");
            throw null;
        }
        y1 y1Var = this.l;
        if (y1Var != null) {
            this.b.E(j, str, y1Var, z);
        } else {
            Intrinsics.m("studyMaterialType");
            throw null;
        }
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void e(com.quizlet.data.interactor.folderstudymaterial.g undoAction) {
        Intrinsics.checkNotNullParameter(undoAction, "undoAction");
        E.A(this.e, this.f, null, new h(this, undoAction, null), 2);
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void f(long j, List tags) {
        Intrinsics.checkNotNullParameter(tags, "tags");
        E.A(this.e, null, null, new k(this, j, tags, null), 3);
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final InterfaceC4992i g() {
        return this.i;
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final q0 i() {
        return this.g;
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final InterfaceC4992i j() {
        return this.j;
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void k(String studyMaterialId, y1 studyMaterialType, AddMaterialFolderData data) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        Intrinsics.checkNotNullParameter(data, "data");
        this.m = studyMaterialId;
        this.l = studyMaterialType;
        if (data.c) {
            this.h.h(new com.quizlet.features.infra.folder.menu.data.o(data.b, new com.quizlet.data.interactor.folderstudymaterial.f(data.a, studyMaterialId, studyMaterialType)));
        } else {
            K k = K.a;
            r(new com.quizlet.features.infra.folder.menu.data.b(data.a, data.b, false, k));
        }
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void l(long j, long j2, String folderTitle) {
        Intrinsics.checkNotNullParameter(folderTitle, "folderTitle");
        E.A(this.e, this.f, null, new g(this, folderTitle, j, j2, null), 2);
    }

    public final void m(LinkedHashSet linkedHashSet, List list) {
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            com.quizlet.features.infra.folder.menu.data.e eVar = (com.quizlet.features.infra.folder.menu.data.e) it2.next();
            long j = eVar.b;
            boolean zContains = linkedHashSet.contains(Long.valueOf(j));
            Long lValueOf = Long.valueOf(j);
            if (zContains) {
                linkedHashSet.remove(lValueOf);
            } else {
                linkedHashSet.add(lValueOf);
            }
            long j2 = eVar.b;
            if (linkedHashSet.contains(Long.valueOf(j2))) {
                linkedHashSet.add(Long.valueOf(eVar.a));
            }
            String str = this.m;
            if (str == null) {
                Intrinsics.m("studyMaterialId");
                throw null;
            }
            y1 y1Var = this.l;
            if (y1Var == null) {
                Intrinsics.m("studyMaterialType");
                throw null;
            }
            boolean zContains2 = linkedHashSet.contains(Long.valueOf(j2));
            this.b.F(eVar.a, y1Var, eVar.c, str, zContains2);
        }
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void n() {
        E.A(this.e, this.f, null, new i(this, null), 2);
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void o(String studyMaterialId, y1 studyMaterialType) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        E.A(this.e, this.f, null, new j(this, studyMaterialId, studyMaterialType, null), 2);
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void p() {
        s0 s0Var;
        Object value;
        do {
            s0Var = this.g;
            value = s0Var.getValue();
        } while (!s0Var.k(value, com.quizlet.features.infra.folder.menu.screenstates.b.a));
        String str = this.m;
        if (str == null) {
            Intrinsics.m("studyMaterialId");
            throw null;
        }
        y1 y1Var = this.l;
        if (y1Var != null) {
            this.b.y(str, y1Var);
        } else {
            Intrinsics.m("studyMaterialType");
            throw null;
        }
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void q(com.quizlet.features.infra.folder.menu.data.g option) {
        Object value;
        Object objC;
        Intrinsics.checkNotNullParameter(option, "option");
        if (Intrinsics.b(option, com.quizlet.features.infra.folder.menu.data.c.a)) {
            this.b.A();
            this.i.h(Unit.a);
            return;
        }
        if (option instanceof com.quizlet.features.infra.folder.menu.data.b) {
            y(new C1279l(false, option, (Object) this, 3));
            return;
        }
        boolean z = option instanceof com.quizlet.features.infra.folder.menu.data.e;
        s0 s0Var = this.g;
        if (!z) {
            if (!(option instanceof com.quizlet.features.infra.folder.menu.data.d)) {
                throw new NoWhenBranchMatchedException();
            }
            com.quizlet.features.infra.folder.menu.data.d dVar = (com.quizlet.features.infra.folder.menu.data.d) option;
            if (s0Var.getValue() instanceof com.quizlet.features.infra.folder.menu.screenstates.c) {
                this.j.h(new com.quizlet.features.infra.folder.menu.screenstates.a(dVar.a, CollectionsKt.w0(dVar.b)));
                return;
            }
            return;
        }
        com.quizlet.features.infra.folder.menu.data.e eVar = (com.quizlet.features.infra.folder.menu.data.e) option;
        do {
            value = s0Var.getValue();
            objC = (com.quizlet.features.infra.folder.menu.screenstates.d) value;
            if (objC instanceof com.quizlet.features.infra.folder.menu.screenstates.c) {
                com.quizlet.features.infra.folder.menu.screenstates.c it2 = (com.quizlet.features.infra.folder.menu.screenstates.c) objC;
                Intrinsics.checkNotNullParameter(it2, "it");
                LinkedHashSet linkedHashSetZ0 = CollectionsKt.z0(it2.b);
                m(linkedHashSetZ0, A.b(eVar));
                objC = com.quizlet.features.infra.folder.menu.screenstates.c.c(it2, AbstractC3409x1.j(linkedHashSetZ0), !linkedHashSetZ0.equals(t(it2.a)));
            }
        } while (!s0Var.k(value, objC));
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void r(com.quizlet.features.infra.folder.menu.data.g option) {
        Intrinsics.checkNotNullParameter(option, "option");
        if (Intrinsics.b(option, com.quizlet.features.infra.folder.menu.data.c.a)) {
            this.b.A();
            this.i.h(Unit.a);
            return;
        }
        boolean z = option instanceof com.quizlet.features.infra.folder.menu.data.b;
        C4203d c4203d = this.f;
        kotlinx.coroutines.internal.d dVar = this.e;
        if (z) {
            com.quizlet.features.infra.folder.menu.data.b bVar = (com.quizlet.features.infra.folder.menu.data.b) option;
            E.A(dVar, c4203d, null, new d(bVar.c, bVar.a, this, bVar.b, null), 2);
        } else if (option instanceof com.quizlet.features.infra.folder.menu.data.e) {
            com.quizlet.features.infra.folder.menu.data.e eVar = (com.quizlet.features.infra.folder.menu.data.e) option;
            E.A(dVar, c4203d, null, new d(eVar.d, eVar.b, this, eVar.c, null), 2);
        } else if (!(option instanceof com.quizlet.features.infra.folder.menu.data.d)) {
            throw new NoWhenBranchMatchedException();
        }
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void s() {
        String str = this.m;
        if (str == null) {
            Intrinsics.m("studyMaterialId");
            throw null;
        }
        y1 y1Var = this.l;
        if (y1Var != null) {
            this.b.z(str, y1Var);
        } else {
            Intrinsics.m("studyMaterialType");
            throw null;
        }
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final InterfaceC4992i u() {
        return new com.quizlet.features.flashcards.helpers.d(this.h, 1);
    }

    public final void v() {
        E.h(this.c, null);
    }

    public final void w(Throwable th) {
        s0 s0Var;
        Object value;
        this.h.h(new com.quizlet.features.infra.folder.menu.data.n(th));
        do {
            s0Var = this.g;
            value = s0Var.getValue();
        } while (!s0Var.k(value, com.quizlet.features.infra.folder.menu.screenstates.b.a));
    }

    public final com.quizlet.features.infra.folder.menu.data.b x(C4169u c4169u) {
        Iterable<C4169u> iterable = c4169u.d;
        if (iterable == null) {
            iterable = K.a;
        }
        ArrayList arrayList = new ArrayList();
        for (C4169u c4169u2 : iterable) {
            arrayList.add(new com.quizlet.features.infra.folder.menu.data.e(c4169u.a, c4169u2.a, c4169u2.b, c4169u2.c));
        }
        if (!arrayList.isEmpty()) {
            Iterable iterable2 = c4169u.d;
            if (iterable2 == null) {
                iterable2 = K.a;
            }
            LinkedHashSet currentTags = new LinkedHashSet();
            Iterator it2 = iterable2.iterator();
            while (it2.hasNext()) {
                currentTags.add(((C4169u) it2.next()).b);
            }
            kotlinx.collections.immutable.e eVarK = AbstractC3409x1.k(currentTags);
            Intrinsics.checkNotNullParameter(currentTags, "currentTags");
            Intrinsics.checkNotNullParameter(currentTags, "currentTags");
            arrayList.add(new com.quizlet.features.infra.folder.menu.data.d(c4169u.a, eVarK, (currentTags.size() < 30 ? EnumC4159q0.a : EnumC4159q0.d) == EnumC4159q0.a));
        }
        return new com.quizlet.features.infra.folder.menu.data.b(c4169u.a, c4169u.b, c4169u.c, arrayList);
    }

    public final void y(Function1 function1) {
        s0 s0Var;
        Object value;
        com.quizlet.features.infra.folder.menu.screenstates.d dVar;
        do {
            s0Var = this.g;
            value = s0Var.getValue();
            dVar = (com.quizlet.features.infra.folder.menu.screenstates.d) value;
            if (dVar instanceof com.quizlet.features.infra.folder.menu.screenstates.c) {
                dVar = (com.quizlet.features.infra.folder.menu.screenstates.d) function1.invoke(dVar);
            }
        } while (!s0Var.k(value, dVar));
    }
}
