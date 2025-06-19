package com.quizlet.features.folders.viewmodel;

import androidx.compose.foundation.gestures.l1;
import androidx.compose.foundation.text.input.internal.C0496b;
import androidx.compose.ui.node.V;
import androidx.datastore.core.C1087t;
import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import androidx.paging.C1319i;
import androidx.paging.C1329n;
import androidx.paging.J0;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.internal.mlkit_vision_camera.K1;
import com.google.android.gms.internal.mlkit_vision_camera.L1;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.quizlet.data.connectivity.NetworkOfflineError;
import com.quizlet.data.exceptions.folder.CourseAlreadyInFolderException;
import com.quizlet.data.model.I1;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.eventlogger.features.folder.FolderLogger;
import com.quizlet.eventlogger.features.study.StudyFunnelEventLogger;
import com.quizlet.features.folders.data.B0;
import com.quizlet.features.folders.data.C4271a0;
import com.quizlet.features.folders.data.C4272b;
import com.quizlet.features.folders.data.C4273b0;
import com.quizlet.features.folders.data.C4274c;
import com.quizlet.features.folders.data.C4275c0;
import com.quizlet.features.folders.data.C4276d;
import com.quizlet.features.folders.data.C4277d0;
import com.quizlet.features.folders.data.C4278e;
import com.quizlet.features.folders.data.C4279e0;
import com.quizlet.features.folders.data.C4280f;
import com.quizlet.features.folders.data.C4281f0;
import com.quizlet.features.folders.data.C4282g;
import com.quizlet.features.folders.data.C4283g0;
import com.quizlet.features.folders.data.C4284h;
import com.quizlet.features.folders.data.C4285h0;
import com.quizlet.features.folders.data.C4286i;
import com.quizlet.features.folders.data.C4287i0;
import com.quizlet.features.folders.data.C4288j;
import com.quizlet.features.folders.data.C4290k;
import com.quizlet.features.folders.data.C4292l;
import com.quizlet.features.folders.data.C4293l0;
import com.quizlet.features.folders.data.C4294m;
import com.quizlet.features.folders.data.C4295m0;
import com.quizlet.features.folders.data.C4297n0;
import com.quizlet.features.folders.data.C4298o;
import com.quizlet.features.folders.data.C4299o0;
import com.quizlet.features.folders.data.C4300p;
import com.quizlet.features.folders.data.C4301p0;
import com.quizlet.features.folders.data.C4302q;
import com.quizlet.features.folders.data.C4303q0;
import com.quizlet.features.folders.data.C4304r0;
import com.quizlet.features.folders.data.C4305s;
import com.quizlet.features.folders.data.C4306s0;
import com.quizlet.features.folders.data.C4309u;
import com.quizlet.features.folders.data.C4310u0;
import com.quizlet.features.folders.data.C4311v;
import com.quizlet.features.folders.data.C4313w;
import com.quizlet.features.folders.data.C4316x0;
import com.quizlet.features.folders.data.C4317y;
import com.quizlet.features.folders.data.C4319z;
import com.quizlet.features.folders.data.EnumC4270a;
import com.quizlet.features.folders.data.InterfaceC4296n;
import com.quizlet.features.folders.data.InterfaceC4307t;
import com.quizlet.features.folders.data.InterfaceC4312v0;
import com.quizlet.features.folders.data.InterfaceC4315x;
import com.quizlet.features.folders.data.K0;
import com.quizlet.features.folders.data.L0;
import com.quizlet.features.folders.data.O0;
import com.quizlet.features.folders.data.P;
import com.quizlet.features.folders.data.P0;
import com.quizlet.features.folders.data.Q;
import com.quizlet.features.folders.data.Q0;
import com.quizlet.features.folders.data.S;
import com.quizlet.features.folders.data.S0;
import com.quizlet.features.folders.data.T;
import com.quizlet.features.folders.data.T0;
import com.quizlet.features.folders.data.U;
import com.quizlet.features.folders.data.U0;
import com.quizlet.features.folders.data.V0;
import com.quizlet.features.folders.data.W;
import com.quizlet.features.folders.data.W0;
import com.quizlet.features.folders.data.X;
import com.quizlet.features.folders.data.X0;
import com.quizlet.features.folders.data.Y;
import com.quizlet.features.folders.viewmodel.usecases.DeleteFolderException;
import com.quizlet.features.folders.viewmodel.usecases.HiddenFolderException;
import com.quizlet.features.folders.viewmodel.usecases.UpdateFolderException;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.generated.enums.EnumC4519s1;
import com.quizlet.generated.enums.EnumC4525u1;
import com.quizlet.generated.enums.y1;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.flow.C4986c;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.Z;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.h0;
import kotlinx.coroutines.flow.j0;
import kotlinx.coroutines.flow.s0;
import kotlinx.coroutines.y0;

@Metadata
/* loaded from: classes3.dex */
public final class N extends w0 implements O {
    public final d0 A;
    public final d0 B;
    public final s0 C;
    public final s0 D;
    public final d0 E;
    public final ArrayList F;
    public final s0 G;
    public final s0 H;
    public X0 I;
    public y0 J;
    public I1 K;
    public final V b;
    public final com.quizlet.features.folders.viewmodel.usecases.k c;
    public final com.quizlet.data.interactor.folderwithcreator.m d;
    public final C1608n e;
    public final com.onetrust.otpublishers.headless.UI.fragment.q f;
    public final com.google.firebase.crashlytics.internal.common.j g;
    public final com.quizlet.features.folders.logging.e h;
    public final io.ktor.client.plugins.api.d i;
    public final l1 j;
    public final com.quizlet.data.interactor.folder.f k;
    public final com.quizlet.data.repository.activitycenter.b l;
    public final com.google.android.gms.internal.appset.e m;
    public final com.quizlet.data.repository.explanations.myexplanations.a n;
    public final com.lyft.android.scissors.b o;
    public final com.quizlet.data.repository.user.a p;
    public final com.quizlet.data.repository.user.a q;
    public final long r;
    public long s;
    public String t;
    public final s0 u;
    public final s0 v;
    public final s0 w;
    public final Z x;
    public final s0 y;
    public final Z z;

    public N(m0 savedStateHandle, V getBasicFolderInfoVMUseCase, com.quizlet.features.folders.viewmodel.usecases.k getFolderStudyMaterialsVMUseCase, com.quizlet.data.interactor.folderwithcreator.m manipulateFolderVMUseCase, C1608n getFolderMenuItemsVMUseCase, com.onetrust.otpublishers.headless.UI.fragment.q manipulateFolderSelectedUseCase, com.google.firebase.crashlytics.internal.common.j saveMaterialsToFolderUseCase, com.quizlet.features.folders.logging.e folderEventLogger, io.ktor.client.plugins.api.d getFolderRecommendationsVMUseCase, l1 canAddToFolderUseCase, com.quizlet.data.interactor.folder.f copyFolderUseCase, com.quizlet.data.repository.activitycenter.b copyFolderStateUseCase, com.google.android.gms.internal.appset.e getSubFoldersVMUseCase, com.quizlet.data.repository.explanations.myexplanations.a validateFolderTagUseCase, com.lyft.android.scissors.b showAddTagTooltipUseCase, com.quizlet.data.repository.user.a studyButtonFeature, com.quizlet.data.repository.user.a studyLearnModeFeature, FolderLogger folderLogger) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(getBasicFolderInfoVMUseCase, "getBasicFolderInfoVMUseCase");
        Intrinsics.checkNotNullParameter(getFolderStudyMaterialsVMUseCase, "getFolderStudyMaterialsVMUseCase");
        Intrinsics.checkNotNullParameter(manipulateFolderVMUseCase, "manipulateFolderVMUseCase");
        Intrinsics.checkNotNullParameter(getFolderMenuItemsVMUseCase, "getFolderMenuItemsVMUseCase");
        Intrinsics.checkNotNullParameter(manipulateFolderSelectedUseCase, "manipulateFolderSelectedUseCase");
        Intrinsics.checkNotNullParameter(saveMaterialsToFolderUseCase, "saveMaterialsToFolderUseCase");
        Intrinsics.checkNotNullParameter(folderEventLogger, "folderEventLogger");
        Intrinsics.checkNotNullParameter(getFolderRecommendationsVMUseCase, "getFolderRecommendationsVMUseCase");
        Intrinsics.checkNotNullParameter(canAddToFolderUseCase, "canAddToFolderUseCase");
        Intrinsics.checkNotNullParameter(copyFolderUseCase, "copyFolderUseCase");
        Intrinsics.checkNotNullParameter(copyFolderStateUseCase, "copyFolderStateUseCase");
        Intrinsics.checkNotNullParameter(getSubFoldersVMUseCase, "getSubFoldersVMUseCase");
        Intrinsics.checkNotNullParameter(validateFolderTagUseCase, "validateFolderTagUseCase");
        Intrinsics.checkNotNullParameter(showAddTagTooltipUseCase, "showAddTagTooltipUseCase");
        Intrinsics.checkNotNullParameter(studyButtonFeature, "studyButtonFeature");
        Intrinsics.checkNotNullParameter(studyLearnModeFeature, "studyLearnModeFeature");
        Intrinsics.checkNotNullParameter(folderLogger, "folderLogger");
        this.b = getBasicFolderInfoVMUseCase;
        this.c = getFolderStudyMaterialsVMUseCase;
        this.d = manipulateFolderVMUseCase;
        this.e = getFolderMenuItemsVMUseCase;
        this.f = manipulateFolderSelectedUseCase;
        this.g = saveMaterialsToFolderUseCase;
        this.h = folderEventLogger;
        this.i = getFolderRecommendationsVMUseCase;
        this.j = canAddToFolderUseCase;
        this.k = copyFolderUseCase;
        this.l = copyFolderStateUseCase;
        this.m = getSubFoldersVMUseCase;
        this.n = validateFolderTagUseCase;
        this.o = showAddTagTooltipUseCase;
        this.p = studyButtonFeature;
        this.q = studyLearnModeFeature;
        Long l = (Long) savedStateHandle.a("folderId");
        if (l == null) {
            throw new IllegalArgumentException("Missing ARG_FOLDER_ID");
        }
        long jLongValue = l.longValue();
        this.r = jLongValue;
        this.s = jLongValue;
        this.t = "ALL";
        this.u = e0.c(com.quizlet.features.folders.data.V.a);
        this.v = e0.c(V0.a);
        s0 s0VarC = e0.c(new O0(false, false));
        this.w = s0VarC;
        com.quizlet.features.folders.addtofolder.viewmodel.usecase.c cVar = new com.quizlet.features.folders.addtofolder.viewmodel.usecase.c(new C1087t(new E(this, null)), new C1087t(new F(this, null)), new G(3, null), 2);
        androidx.lifecycle.viewmodel.internal.a aVarJ = p0.j(this);
        j0 j0Var = h0.a;
        Z zX = e0.x(cVar, aVarJ, j0Var, new S0(false, false));
        H h = new H(2, null);
        int i = kotlinx.coroutines.flow.G.a;
        this.x = e0.x(new J0(new com.quizlet.features.folders.addtofolder.viewmodel.usecase.c(new kotlinx.coroutines.flow.internal.m(new C1319i((Object) h, (kotlin.coroutines.h) null, 13), s0VarC, kotlin.coroutines.n.a, -2, kotlinx.coroutines.channels.a.a), zX, new I(3, null), 2), new J(2, null), 5), p0.j(this), j0Var, new T0(kotlinx.collections.immutable.implementations.immutableList.g.c, false));
        C4316x0 c4316x0 = C4316x0.a;
        s0 s0VarC2 = e0.c(c4316x0);
        this.y = s0VarC2;
        this.z = e0.x(new com.quizlet.features.folders.addtofolder.viewmodel.usecase.c(new C1329n(s0VarC, 1), s0VarC2, new C4328i(3, 4, N.class, this, "filterOutRecommendationsAlreadyInFolder", "filterOutRecommendationsAlreadyInFolder(Ljava/util/List;Lcom/quizlet/features/folders/data/FolderRecommendationsState;)Lcom/quizlet/features/folders/data/FolderRecommendationsState;"), 2), p0.j(this), j0Var, c4316x0);
        this.A = e0.b(0, 1, null, 5);
        this.B = e0.b(0, 1, null, 5);
        this.C = e0.c(com.quizlet.features.folders.menu.k.a);
        this.D = e0.c(com.quizlet.features.folders.menu.s.a);
        this.E = e0.b(0, 1, null, 5);
        this.F = new ArrayList();
        Boolean bool = Boolean.FALSE;
        this.G = e0.c(bool);
        this.H = e0.c(bool);
        this.I = new X0(0L, 0L, "");
        folderLogger.setScreenName("folder_page");
        folderEventLogger.a.K(jLongValue, jLongValue, 3);
        StudyFunnelEventLogger.a(folderEventLogger.b, EnumC4519s1.CONTAINER_PAGE_VIEW, l, 3, folderEventLogger.a(String.valueOf(jLongValue)), EnumC4525u1.FOLDER_PAGE, null, 0, 0, null, null, null, null, 3840);
        com.quizlet.features.folders.logging.e.b(folderEventLogger, jLongValue, "course_folder_viewed", null, null, null, null, null, 248);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new C4324e(this, null), 3);
    }

    public static final Object A(N n, kotlin.coroutines.jvm.internal.i iVar) {
        V v = n.b;
        androidx.work.impl.model.v vVar = (androidx.work.impl.model.v) v.b;
        InterfaceC4992i interfaceC4992iS = e0.s(e0.m(new C1087t(new com.quizlet.data.repository.folderwithcreator.c((com.quizlet.data.repository.folderwithcreator.e) vVar.b, n.r, null))), (AbstractC5040y) vVar.c);
        InterfaceC4992i interfaceC4992iM = e0.m(K1.f(((com.quizlet.remote.connectivity.b) ((com.quizlet.data.connectivity.a) v.d)).a.a));
        com.quizlet.data.repository.course.membership.c cVar = (com.quizlet.data.repository.course.membership.c) v.e;
        cVar.getClass();
        io.reactivex.rxjava3.core.i iVarM = L1.e((AbstractC5040y) cVar.c, new com.quizlet.featuregate.features.folder.d(cVar, null)).m();
        Intrinsics.checkNotNullExpressionValue(iVarM, "toObservable(...)");
        C4986c c4986cF = K1.f(iVarM);
        io.reactivex.rxjava3.core.i iVarM2 = ((com.quizlet.data.repository.user.a) v.g).w().m();
        Intrinsics.checkNotNullExpressionValue(iVarM2, "toObservable(...)");
        C4986c c4986cF2 = K1.f(iVarM2);
        io.reactivex.rxjava3.core.i iVarM3 = ((com.quizlet.data.repository.user.a) v.h).w().m();
        Intrinsics.checkNotNullExpressionValue(iVarM3, "toObservable(...)");
        Object objI = e0.i(new J0(new androidx.compose.material3.internal.H(20, new InterfaceC4992i[]{interfaceC4992iS, interfaceC4992iM, c4986cF, c4986cF2, K1.f(iVarM3)}, new com.quizlet.features.folders.viewmodel.usecases.e(v, null)), new com.google.firebase.sessions.H(3, 2, null)), new s(n, null), iVar);
        return objI == kotlin.coroutines.intrinsics.a.a ? objI : Unit.a;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object B(com.quizlet.features.folders.viewmodel.N r4, com.quizlet.features.folders.viewmodel.usecases.c r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4.getClass()
            boolean r0 = r6 instanceof com.quizlet.features.folders.viewmodel.t
            if (r0 == 0) goto L16
            r0 = r6
            com.quizlet.features.folders.viewmodel.t r0 = (com.quizlet.features.folders.viewmodel.t) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.m = r1
            goto L1b
        L16:
            com.quizlet.features.folders.viewmodel.t r0 = new com.quizlet.features.folders.viewmodel.t
            r0.<init>(r4, r6)
        L1b:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L34
            if (r2 != r3) goto L2c
            com.quizlet.features.folders.viewmodel.N r4 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L44
        L2c:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r4
            r0.m = r3
            com.google.android.gms.ads.internal.client.n r6 = r4.e
            java.lang.Object r6 = r6.u(r5, r0)
            if (r6 != r1) goto L44
            return r1
        L44:
            java.util.List r6 = (java.util.List) r6
            kotlinx.coroutines.flow.s0 r5 = r4.C
        L48:
            java.lang.Object r0 = r5.getValue()
            r1 = r0
            com.quizlet.features.folders.menu.m r1 = (com.quizlet.features.folders.menu.m) r1
            boolean r1 = r6.isEmpty()
            if (r1 == 0) goto L58
            com.quizlet.features.folders.menu.k r1 = com.quizlet.features.folders.menu.k.a
            goto L62
        L58:
            java.util.ArrayList r1 = r4.F
            r1.clear()
            r1.addAll(r6)
            com.quizlet.features.folders.menu.j r1 = com.quizlet.features.folders.menu.j.a
        L62:
            boolean r0 = r5.k(r0, r1)
            if (r0 == 0) goto L48
            kotlin.Unit r4 = kotlin.Unit.a
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.folders.viewmodel.N.B(com.quizlet.features.folders.viewmodel.N, com.quizlet.features.folders.viewmodel.usecases.c, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final Object C(N n, kotlin.coroutines.jvm.internal.i iVar) {
        long j = n.s;
        ArrayList arrayList = com.quizlet.features.folders.viewmodel.usecases.k.c;
        com.quizlet.features.folders.viewmodel.usecases.k kVar = n.c;
        Object objB = new J0(e0.m(new androidx.compose.material3.internal.H(2, kVar.a.c(j, arrayList), kVar)), new com.google.firebase.sessions.H(3, 3, null)).b(new C0496b(n, 11), iVar);
        return objB == kotlin.coroutines.intrinsics.a.a ? objB : Unit.a;
    }

    /* JADX WARN: Code restructure failed: missing block: B:20:0x0061, code lost:
    
        if (((kotlinx.coroutines.flow.InterfaceC4992i) r8).b(r2, r0) == r1) goto L21;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object D(com.quizlet.features.folders.viewmodel.N r6, boolean r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r6.getClass()
            boolean r0 = r8 instanceof com.quizlet.features.folders.viewmodel.v
            if (r0 == 0) goto L16
            r0 = r8
            com.quizlet.features.folders.viewmodel.v r0 = (com.quizlet.features.folders.viewmodel.v) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.n = r1
            goto L1b
        L16:
            com.quizlet.features.folders.viewmodel.v r0 = new com.quizlet.features.folders.viewmodel.v
            r0.<init>(r6, r8)
        L1b:
            java.lang.Object r8 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3d
            if (r2 == r4) goto L35
            if (r2 != r3) goto L2d
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L64
        L2d:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L35:
            boolean r7 = r0.k
            com.quizlet.features.folders.viewmodel.N r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L51
        L3d:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r0.j = r6
            r0.k = r7
            r0.n = r4
            com.google.android.gms.internal.appset.e r8 = r6.m
            long r4 = r6.r
            java.lang.Object r8 = r8.o(r4, r0)
            if (r8 != r1) goto L51
            goto L63
        L51:
            kotlinx.coroutines.flow.i r8 = (kotlinx.coroutines.flow.InterfaceC4992i) r8
            com.quizlet.features.folders.viewmodel.x r2 = new com.quizlet.features.folders.viewmodel.x
            r2.<init>(r6, r7)
            r6 = 0
            r0.j = r6
            r0.n = r3
            java.lang.Object r6 = r8.b(r2, r0)
            if (r6 != r1) goto L64
        L63:
            return r1
        L64:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.folders.viewmodel.N.D(com.quizlet.features.folders.viewmodel.N, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:33:0x00ab A[PHI: r10 r11
  0x00ab: PHI (r10v3 java.lang.Object) = (r10v2 java.lang.Object), (r10v2 java.lang.Object), (r10v10 java.lang.Object) binds: [B:29:0x0090, B:31:0x00a8, B:16:0x0038] A[DONT_GENERATE, DONT_INLINE]
  0x00ab: PHI (r11v6 com.quizlet.features.folders.viewmodel.N) = 
  (r11v5 com.quizlet.features.folders.viewmodel.N)
  (r11v5 com.quizlet.features.folders.viewmodel.N)
  (r11v10 com.quizlet.features.folders.viewmodel.N)
 binds: [B:29:0x0090, B:31:0x00a8, B:16:0x0038] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00b1  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object E(com.quizlet.features.folders.viewmodel.N r10, java.util.List r11, kotlin.coroutines.jvm.internal.c r12) {
        /*
            boolean r0 = r12 instanceof com.quizlet.features.folders.viewmodel.y
            if (r0 == 0) goto L13
            r0 = r12
            com.quizlet.features.folders.viewmodel.y r0 = (com.quizlet.features.folders.viewmodel.y) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.features.folders.viewmodel.y r0 = new com.quizlet.features.folders.viewmodel.y
            r0.<init>(r10, r12)
        L18:
            java.lang.Object r12 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 3
            r4 = 2
            r5 = 1
            if (r2 == 0) goto L4e
            if (r2 == r5) goto L41
            if (r2 == r4) goto L38
            if (r2 != r3) goto L30
            com.quizlet.features.folders.viewmodel.N r10 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto Lc8
        L30:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r11 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r11)
            throw r10
        L38:
            java.lang.Object r10 = r0.k
            com.quizlet.features.folders.viewmodel.N r11 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto Lab
        L41:
            com.quizlet.features.folders.viewmodel.N r10 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r12)
            kotlin.r r12 = (kotlin.r) r12
            java.lang.Object r11 = r12.a
        L4a:
            r9 = r11
            r11 = r10
            r10 = r9
            goto L8c
        L4e:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            com.quizlet.data.model.I1 r12 = r10.K
            if (r12 == 0) goto Lcc
            java.util.ArrayList r2 = new java.util.ArrayList
            r6 = 10
            int r6 = kotlin.collections.C.q(r11, r6)
            r2.<init>(r6)
            java.util.Iterator r11 = r11.iterator()
        L64:
            boolean r6 = r11.hasNext()
            if (r6 == 0) goto L7d
            java.lang.Object r6 = r11.next()
            com.quizlet.data.model.CreatedFolder r6 = (com.quizlet.data.model.CreatedFolder) r6
            long r6 = r6.a()
            java.lang.Long r8 = new java.lang.Long
            r8.<init>(r6)
            r2.add(r8)
            goto L64
        L7d:
            kotlin.collections.K r11 = kotlin.collections.K.a
            r0.j = r10
            r0.n = r5
            com.google.firebase.crashlytics.internal.common.j r5 = r10.g
            java.lang.Object r11 = r5.i(r12, r2, r11, r0)
            if (r11 != r1) goto L4a
            goto Lc6
        L8c:
            kotlin.p r12 = kotlin.r.b
            boolean r12 = r10 instanceof kotlin.q
            if (r12 != 0) goto Lab
            r12 = r10
            com.quizlet.features.folders.viewmodel.usecases.d r12 = (com.quizlet.features.folders.viewmodel.usecases.d) r12
            kotlinx.coroutines.flow.d0 r12 = r11.E
            com.quizlet.features.folders.data.A0 r2 = new com.quizlet.features.folders.data.A0
            com.quizlet.features.infra.folder.menu.data.v r5 = com.quizlet.features.infra.folder.menu.data.v.a
            r2.<init>(r5)
            r0.j = r11
            r0.k = r10
            r0.n = r4
            java.lang.Object r12 = r12.emit(r2, r0)
            if (r12 != r1) goto Lab
            goto Lc6
        Lab:
            java.lang.Throwable r12 = kotlin.r.a(r10)
            if (r12 == 0) goto Lc9
            kotlinx.coroutines.flow.d0 r12 = r11.E
            com.quizlet.features.folders.data.A0 r2 = new com.quizlet.features.folders.data.A0
            com.quizlet.features.infra.folder.menu.data.t r4 = com.quizlet.features.infra.folder.menu.data.t.a
            r2.<init>(r4)
            r0.j = r11
            r0.k = r10
            r0.n = r3
            java.lang.Object r10 = r12.emit(r2, r0)
            if (r10 != r1) goto Lc7
        Lc6:
            return r1
        Lc7:
            r10 = r11
        Lc8:
            r11 = r10
        Lc9:
            r10 = 0
            r11.K = r10
        Lcc:
            kotlin.Unit r10 = kotlin.Unit.a
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.folders.viewmodel.N.E(com.quizlet.features.folders.viewmodel.N, java.util.List, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final void F(N n) {
        Object value;
        Object objA;
        s0 s0Var = n.u;
        do {
            value = s0Var.getValue();
            objA = (W) value;
            U u = objA instanceof U ? (U) objA : null;
            if (u != null) {
                objA = U.a(u, Q0.a(((U) objA).a, null, null, false, null, 0L, 1048319), false, 2);
            }
        } while (!s0Var.k(value, objA));
        n.B.h(C4283g0.a);
    }

    public final Q0 G() {
        Object value = this.u.getValue();
        U u = value instanceof U ? (U) value : null;
        if (u != null) {
            return u.a;
        }
        return null;
    }

    public final String H() {
        com.quizlet.features.infra.models.folders.c cVar;
        W0 w0 = (W0) this.v.getValue();
        int iC = w0.c();
        Integer numValueOf = Integer.valueOf(iC);
        if (iC <= 0) {
            numValueOf = null;
        }
        if (numValueOf == null || (cVar = (com.quizlet.features.infra.models.folders.c) CollectionsKt.O(numValueOf.intValue(), w0.a())) == null) {
            return null;
        }
        return cVar.c;
    }

    public final void I(String clickSource) {
        String tagName = this.t;
        com.quizlet.features.folders.logging.e eVar = this.h;
        eVar.getClass();
        Intrinsics.checkNotNullParameter(tagName, "tagName");
        Intrinsics.checkNotNullParameter(clickSource, "clickSource");
        EventLoggerExt.a(eVar.a, "folder_add_new_button_clicked", new com.quizlet.eventlogger.features.learnonboarding.a(tagName, this.r, clickSource, 2));
        this.B.h(com.quizlet.features.folders.data.Z.a);
    }

    public final void J(boolean z) {
        s0 s0Var;
        Object value;
        do {
            s0Var = this.w;
            value = s0Var.getValue();
        } while (!s0Var.k(value, new O0(z, ((P0) value).b())));
        kotlinx.coroutines.E.A(p0.j(this), null, null, new p(this, null, z), 3);
    }

    public final void K() {
        s0 s0Var;
        Object value;
        Object objD;
        do {
            s0Var = this.w;
            value = s0Var.getValue();
            objD = (P0) value;
            L0 l0 = objD instanceof L0 ? (L0) objD : null;
            if (l0 != null) {
                objD = L0.d(l0, null, false, null, null, 11);
            }
        } while (!s0Var.k(value, objD));
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void L(T event) {
        com.quizlet.qutils.string.g eVar;
        String string;
        Object value;
        kotlin.collections.K k;
        Object value2;
        Object value3;
        Object value4;
        Object objD;
        String str;
        Object value5;
        Object value6;
        Pair pair;
        Intrinsics.checkNotNullParameter(event, "event");
        boolean z = event instanceof InterfaceC4315x;
        d0 d0Var = this.A;
        com.quizlet.features.folders.logging.e eVar2 = this.h;
        if (z) {
            InterfaceC4315x interfaceC4315x = (InterfaceC4315x) event;
            if (interfaceC4315x instanceof C4280f) {
                pair = new Pair(new C4310u0(((C4280f) interfaceC4315x).a), null);
            } else if (interfaceC4315x instanceof C4288j) {
                C4288j c4288j = (C4288j) interfaceC4315x;
                pair = new Pair(new C4306s0(c4288j.a), new com.quizlet.features.folders.logging.f(this.r, c4288j.a, y1.TEXTBOOK_EXERCISE, c4288j.c, Integer.valueOf(c4288j.b), this.t, 144));
            } else if (interfaceC4315x instanceof C4292l) {
                C4292l c4292l = (C4292l) interfaceC4315x;
                pair = new Pair(new C4297n0(c4292l.a), new com.quizlet.features.folders.logging.f(this.r, String.valueOf(c4292l.a), y1.FOLDER, c4292l.c, Integer.valueOf(c4292l.b), this.t, 144));
            } else if (interfaceC4315x instanceof C4319z) {
                C4319z c4319z = (C4319z) interfaceC4315x;
                pair = new Pair(new C4301p0(c4319z.a), new com.quizlet.features.folders.logging.f(this.r, c4319z.a, y1.NOTE, c4319z.c, Integer.valueOf(c4319z.b), this.t, 144));
            } else if (interfaceC4315x instanceof com.quizlet.features.folders.data.B) {
                com.quizlet.features.folders.data.B b = (com.quizlet.features.folders.data.B) interfaceC4315x;
                pair = new Pair(new C4295m0(b.a), new com.quizlet.features.folders.logging.f(this.r, b.a, y1.EXPLANATION_QUESTION, b.c, Integer.valueOf(b.b), this.t, 144));
            } else if (interfaceC4315x instanceof com.quizlet.features.folders.data.L) {
                com.quizlet.features.folders.data.L l = (com.quizlet.features.folders.data.L) interfaceC4315x;
                pair = new Pair(new C4303q0(l.a), new com.quizlet.features.folders.logging.f(this.r, String.valueOf(l.a), y1.SET, l.c, Integer.valueOf(l.b), this.t, 144));
            } else {
                if (!(interfaceC4315x instanceof P)) {
                    throw new NoWhenBranchMatchedException();
                }
                P p = (P) interfaceC4315x;
                pair = new Pair(new C4304r0(p.a), new com.quizlet.features.folders.logging.f(this.r, p.a, y1.TEXTBOOK, p.c, Integer.valueOf(p.b), this.t, 144));
            }
            InterfaceC4312v0 interfaceC4312v0 = (InterfaceC4312v0) pair.a;
            com.quizlet.features.folders.logging.f fVar = (com.quizlet.features.folders.logging.f) pair.b;
            d0Var.h(interfaceC4312v0);
            if (fVar != null) {
                eVar2.c(fVar);
                return;
            }
            return;
        }
        boolean z2 = event instanceof InterfaceC4307t;
        d0 d0Var2 = this.B;
        boolean z3 = false;
        long j = this.r;
        if (z2) {
            InterfaceC4307t interfaceC4307t = (InterfaceC4307t) event;
            if (!(interfaceC4307t instanceof C4309u)) {
                boolean zB = Intrinsics.b(interfaceC4307t, C4305s.a);
                s0 s0Var = this.C;
                if (zB) {
                    do {
                        value6 = s0Var.getValue();
                    } while (!s0Var.k(value6, com.quizlet.features.folders.menu.j.a));
                    return;
                } else {
                    if (!Intrinsics.b(interfaceC4307t, com.quizlet.features.folders.data.r.a)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    eVar2.getClass();
                    EventLoggerExt.a(eVar2.a, "folder_more_options_clicked", new com.braze.requests.framework.m(9, j));
                    do {
                        value5 = s0Var.getValue();
                    } while (!s0Var.k(value5, new com.quizlet.features.folders.menu.l(this.F)));
                    return;
                }
            }
            com.quizlet.features.folders.menu.i iVar = ((C4309u) interfaceC4307t).a;
            if (Intrinsics.b(iVar, com.quizlet.features.folders.menu.f.a)) {
                eVar2.getClass();
                EventLoggerExt.a(eVar2.a, "folder_delete_clicked", new com.braze.requests.framework.m(11, j));
                d0Var2.h(C4287i0.a);
                return;
            }
            if (Intrinsics.b(iVar, com.quizlet.features.folders.menu.g.a)) {
                eVar2.getClass();
                EventLoggerExt.a(eVar2.a, "folder_edit_clicked", new com.braze.requests.framework.m(7, j));
                d0Var2.h(C4275c0.a);
                return;
            }
            if (!(iVar instanceof com.quizlet.features.folders.menu.h)) {
                if (Intrinsics.b(iVar, com.quizlet.features.folders.menu.d.a)) {
                    I("folder_page_top_menu");
                    return;
                } else {
                    if (!(iVar instanceof com.quizlet.features.folders.menu.e)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    M();
                    return;
                }
            }
            com.quizlet.features.folders.menu.h hVar = (com.quizlet.features.folders.menu.h) iVar;
            String str2 = hVar.a;
            eVar2.getClass();
            EventLoggerExt.a(eVar2.a, "folder_share_clicked", new com.braze.requests.framework.m(12, j));
            if (str2 == null) {
                this.E.h(new B0(R.string.folder_cannot_share));
                return;
            }
            Object[] args = new Object[0];
            Intrinsics.checkNotNullParameter(args, "args");
            d0Var2.h(new C4285h0(new com.quizlet.features.infra.models.share.a(str2, "folder-page-share", new com.quizlet.qutils.string.f(R.string.share_folder, C4933y.P(args)), new androidx.navigation.internal.h(hVar.b, 22), new com.quizlet.features.folders.composables.J(this, 1))));
            return;
        }
        String str3 = "";
        if (event instanceof C4290k) {
            C4290k c4290k = (C4290k) event;
            if (!(c4290k instanceof C4290k)) {
                throw new NoWhenBranchMatchedException();
            }
            com.quizlet.features.folders.menu.c cVar = c4290k.a;
            long j2 = this.s;
            Q0 q0G = G();
            if (q0G != null && (str = q0G.a) != null) {
                str3 = str;
            }
            AddMaterialFolderData addMaterialFolderData = new AddMaterialFolderData(str3, j2, false);
            if (Intrinsics.b(cVar, com.quizlet.features.folders.menu.a.a)) {
                kotlinx.coroutines.E.A(p0.j(this), null, null, new C4329j(this, addMaterialFolderData, null), 3);
                return;
            } else {
                if (!Intrinsics.b(cVar, com.quizlet.features.folders.menu.b.a)) {
                    throw new NoWhenBranchMatchedException();
                }
                long j3 = this.s;
                eVar2.getClass();
                EventLoggerExt.a(eVar2.a, "folder_add_new_study_guide_click", new com.braze.requests.framework.m(13, j3));
                d0Var.h(new C4293l0(addMaterialFolderData));
                return;
            }
        }
        if (Intrinsics.b(event, C4282g.a)) {
            kotlinx.coroutines.E.A(p0.j(this), null, null, new C4326g(this, null), 3);
            return;
        }
        if (event instanceof C4294m) {
            C4294m c4294m = (C4294m) event;
            P(c4294m.b, c4294m.c, c4294m.a, false);
            return;
        }
        if (event instanceof C4284h) {
            C4284h c4284h = (C4284h) event;
            kotlinx.coroutines.E.A(p0.j(this), null, null, new C4327h(this, c4284h.a, c4284h.b, null), 3);
            return;
        }
        if (event instanceof Q) {
            kotlinx.coroutines.E.A(p0.j(this), null, null, new K(this, ((Q) event).a, null), 3);
            return;
        }
        if (Intrinsics.b(event, com.quizlet.features.folders.data.G.a)) {
            Q(true);
            return;
        }
        if (Intrinsics.b(event, com.quizlet.features.folders.data.E.a)) {
            Q(false);
            return;
        }
        boolean z4 = event instanceof com.quizlet.features.folders.data.H;
        s0 s0Var2 = this.w;
        if (!z4) {
            if (Intrinsics.b(event, com.quizlet.features.folders.data.F.a)) {
                K();
                return;
            }
            if (event instanceof com.quizlet.features.folders.data.I) {
                K0 sortType = ((com.quizlet.features.folders.data.I) event).a;
                eVar2.getClass();
                Intrinsics.checkNotNullParameter(sortType, "sortType");
                EventLoggerExt.a(eVar2.a, "folder_sorting_changed", new com.quizlet.eventlogger.features.learnonboarding.a(eVar2, j, sortType, 1));
                do {
                    value4 = s0Var2.getValue();
                    objD = (P0) value4;
                    L0 l0 = objD instanceof L0 ? (L0) objD : null;
                    if (l0 != null) {
                        objD = L0.d(l0, null, false, null, sortType, 7);
                    }
                } while (!s0Var2.k(value4, objD));
                return;
            }
            if (Intrinsics.b(event, com.quizlet.features.folders.data.J.a)) {
                eVar2.getClass();
                EventLoggerExt.a(eVar2.a, "folder_sorting_option_clicked", new com.braze.requests.framework.m(14, j));
                return;
            }
            if (Intrinsics.b(event, C4311v.a)) {
                kotlinx.coroutines.E.A(p0.j(this), null, null, new C4331l(this, null), 3);
                return;
            }
            if (event instanceof C4272b) {
                kotlinx.coroutines.E.A(p0.j(this), null, null, new C4330k(this, ((C4272b) event).a, null), 3);
                return;
            }
            if (event instanceof C4313w) {
                C4313w c4313w = (C4313w) event;
                com.quizlet.ui.models.content.listitem.o oVar = c4313w.a;
                eVar2.d(new com.quizlet.features.folders.logging.f(this.s, oVar.d(), oVar.b(), c4313w.c, Integer.valueOf(c4313w.b), null, OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_BACKWARD_COMPATIBILITY));
                return;
            }
            if (event instanceof S) {
                List list = ((S) event).a;
                P0 p0 = (P0) s0Var2.getValue();
                do {
                    value3 = s0Var2.getValue();
                } while (!s0Var2.k(value3, new O0(false, false)));
                kotlinx.coroutines.E.A(p0.j(this), null, null, new q(p0, this, list, null), 3);
                return;
            }
            if (event instanceof C4276d) {
                I(((C4276d) event).a);
                return;
            }
            if (Intrinsics.b(event, com.quizlet.features.folders.data.D.a)) {
                J(false);
                return;
            }
            if (Intrinsics.b(event, com.quizlet.features.folders.data.A.a)) {
                J(true);
                return;
            }
            if (Intrinsics.b(event, C4278e.a)) {
                O(EnumC4270a.b);
                Q0 q0G2 = G();
                if (q0G2 != null && q0G2.i) {
                    z3 = true;
                }
                eVar2.getClass();
                EventLoggerExt.a(eVar2.a, "folder_save_public_folder", new com.quizlet.features.folders.logging.c(z3, j, 1));
                kotlinx.coroutines.E.A(p0.j(this), null, null, new C4325f(this, null), 3);
                return;
            }
            if (event instanceof com.quizlet.features.folders.data.C) {
                X0 x0 = this.I;
                P(x0.b, x0.c, x0.a, true);
                return;
            }
            if (event instanceof com.quizlet.features.folders.data.M) {
                com.quizlet.features.folders.data.M m = (com.quizlet.features.folders.data.M) event;
                long j4 = m.a;
                if (j4 == this.s) {
                    return;
                }
                y0 y0Var = this.J;
                if (y0Var != null) {
                    y0Var.j(null);
                }
                this.s = j4;
                this.J = kotlinx.coroutines.E.A(p0.j(this), null, null, new r(m.b, this, j4, null), 3);
                return;
            }
            if (event instanceof C4317y) {
                kotlinx.coroutines.E.A(p0.j(this), null, null, new C4332m(this, ((C4317y) event).a, null), 3);
                return;
            }
            if (event instanceof com.quizlet.features.folders.data.O) {
                kotlinx.coroutines.E.A(p0.j(this), null, null, new C(this, ((com.quizlet.features.folders.data.O) event).a, null), 3);
                return;
            }
            if (!(event instanceof InterfaceC4296n)) {
                if (Intrinsics.b(event, C4274c.a)) {
                    eVar2.getClass();
                    EventLoggerExt.a(eVar2.a, "folder_add_tag_clicked", new com.braze.requests.framework.m(8, j));
                    M();
                    return;
                }
                if (event instanceof C4286i) {
                    com.quizlet.features.infra.models.folders.c cVar2 = ((C4286i) event).a;
                    String tagName = cVar2.c;
                    eVar2.getClass();
                    Intrinsics.checkNotNullParameter(tagName, "tagName");
                    com.quizlet.features.folders.logging.e.b(eVar2, this.r, "edit_folder_edit_tag_clicked", null, null, null, "folder_page", new androidx.navigation.internal.h(tagName, 21), 60);
                    d0Var2.h(new C4277d0(cVar2.a, cVar2.c));
                    return;
                }
                if (event instanceof com.quizlet.features.folders.data.N) {
                    kotlinx.coroutines.E.A(p0.j(this), null, null, new B(this, null, ((com.quizlet.features.folders.data.N) event).a), 3);
                    return;
                }
                if (!(event instanceof com.quizlet.features.folders.data.K)) {
                    throw new NoWhenBranchMatchedException();
                }
                com.quizlet.features.infra.folder.study.data.a aVar = ((com.quizlet.features.folders.data.K) event).a;
                Object value7 = s0Var2.getValue();
                L0 l02 = value7 instanceof L0 ? (L0) value7 : null;
                kotlinx.collections.immutable.b bVar = l02 != null ? l02.a : null;
                if (bVar != null) {
                    ArrayList arrayList = new ArrayList();
                    for (Object obj : bVar) {
                        if (obj instanceof com.quizlet.ui.models.content.listitem.l) {
                            arrayList.add(obj);
                        }
                    }
                    if (!Intrinsics.b(aVar, com.quizlet.features.infra.folder.study.data.a.a)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
                    Iterator it2 = arrayList.iterator();
                    while (it2.hasNext()) {
                        arrayList2.add(Long.valueOf(((com.quizlet.ui.models.content.listitem.l) it2.next()).a.a));
                    }
                    StudyableModelData.StudyFolder studyFolder = new StudyableModelData.StudyFolder(j, CollectionsKt.A0(arrayList2));
                    Q0 q0G3 = G();
                    if (q0G3 == null || (string = q0G3.a) == null) {
                        Intrinsics.checkNotNullParameter("", "string");
                        eVar = new com.quizlet.qutils.string.e("");
                    } else {
                        String strH = H();
                        if (strH != null) {
                            Object[] args2 = {string, strH};
                            Intrinsics.checkNotNullParameter(args2, "args");
                            eVar = new com.quizlet.qutils.string.f(R.string.study_subfolder_title, C4933y.P(args2));
                        } else {
                            Intrinsics.checkNotNullParameter(string, "string");
                            eVar = new com.quizlet.qutils.string.e(string);
                        }
                    }
                    d0Var.h(new C4299o0(studyFolder, eVar));
                    return;
                }
                return;
            }
            InterfaceC4296n interfaceC4296n = (InterfaceC4296n) event;
            boolean z5 = interfaceC4296n instanceof C4298o;
            s0 s0Var3 = this.D;
            if (z5) {
                long j5 = this.s;
                eVar2.getClass();
                com.quizlet.features.folders.logging.e.b(eVar2, j5, "folder_item_more_options_clicked", null, null, null, null, null, 252);
                C4298o c4298o = (C4298o) interfaceC4296n;
                String str4 = c4298o.a;
                W0 w0 = (W0) this.v.getValue();
                boolean z6 = w0 instanceof U0;
                y1 y1Var = c4298o.b;
                if (z6) {
                    ArrayList arrayList3 = new ArrayList();
                    kotlinx.collections.immutable.b bVar2 = ((U0) w0).a;
                    if (bVar2 == null || !bVar2.isEmpty()) {
                        Iterator<E> it3 = bVar2.iterator();
                        while (it3.hasNext()) {
                            if (((com.quizlet.features.infra.models.folders.c) it3.next()).b == com.quizlet.features.infra.models.folders.b.b) {
                                arrayList3.add(new com.quizlet.features.folders.menu.n(str4, y1Var));
                                break;
                            }
                        }
                        arrayList3.add(new com.quizlet.features.folders.menu.o(str4, y1Var));
                        arrayList3.add(new com.quizlet.features.folders.menu.p(str4, y1Var));
                        k = arrayList3;
                    } else {
                        arrayList3.add(new com.quizlet.features.folders.menu.o(str4, y1Var));
                        arrayList3.add(new com.quizlet.features.folders.menu.p(str4, y1Var));
                        k = arrayList3;
                    }
                } else {
                    if (!Intrinsics.b(w0, V0.a)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    k = kotlin.collections.K.a;
                }
                do {
                    value2 = s0Var3.getValue();
                } while (!s0Var3.k(value2, new com.quizlet.features.folders.menu.t(k, c4298o.a, y1Var)));
                return;
            }
            if (Intrinsics.b(interfaceC4296n, C4300p.a)) {
                do {
                    value = s0Var3.getValue();
                } while (!s0Var3.k(value, com.quizlet.features.folders.menu.r.a));
                return;
            }
            if (!(interfaceC4296n instanceof C4302q)) {
                throw new NoWhenBranchMatchedException();
            }
            com.quizlet.features.folders.menu.q qVar = ((C4302q) interfaceC4296n).a;
            if (qVar instanceof com.quizlet.features.folders.menu.n) {
                com.quizlet.features.folders.menu.n nVar = (com.quizlet.features.folders.menu.n) qVar;
                String studyMaterialId = nVar.a;
                eVar2.getClass();
                Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
                y1 studyMaterialType = nVar.b;
                Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
                com.quizlet.features.folders.logging.e.b(eVar2, this.r, "folder_item_add_tag_clicked", null, studyMaterialId, studyMaterialType, null, null, 204);
                d0Var2.h(new C4271a0(nVar.a, nVar.b));
                return;
            }
            if (!(qVar instanceof com.quizlet.features.folders.menu.o)) {
                if (!(qVar instanceof com.quizlet.features.folders.menu.p)) {
                    throw new NoWhenBranchMatchedException();
                }
                com.quizlet.features.folders.menu.p pVar = (com.quizlet.features.folders.menu.p) qVar;
                kotlinx.coroutines.E.A(p0.j(this), null, null, new C4327h(this, pVar.a, pVar.b, null), 3);
                return;
            }
            com.quizlet.features.folders.menu.o oVar2 = (com.quizlet.features.folders.menu.o) qVar;
            String studyMaterialId2 = oVar2.a;
            eVar2.getClass();
            Intrinsics.checkNotNullParameter(studyMaterialId2, "studyMaterialId");
            y1 studyMaterialType2 = oVar2.b;
            Intrinsics.checkNotNullParameter(studyMaterialType2, "studyMaterialType");
            com.quizlet.features.folders.logging.e.b(eVar2, this.r, "folder_item_add_tag_clicked", null, studyMaterialId2, studyMaterialType2, null, null, 204);
            this.K = new I1(oVar2.a, oVar2.b);
            M();
            return;
        }
        String str5 = ((com.quizlet.features.folders.data.H) event).a;
        while (true) {
            Object value8 = s0Var2.getValue();
            Object objD2 = (P0) value8;
            L0 l03 = objD2 instanceof L0 ? (L0) objD2 : null;
            if (l03 != null) {
                objD2 = L0.d(l03, null, false, str5, null, 11);
            }
            String str6 = str5;
            if (s0Var2.k(value8, objD2)) {
                return;
            } else {
                str5 = str6;
            }
        }
    }

    public final void M() {
        String str;
        d0 d0Var = this.B;
        kotlinx.collections.immutable.b<com.quizlet.features.infra.models.folders.c> bVarA = ((W0) this.v.getValue()).a();
        ArrayList arrayList = new ArrayList();
        for (com.quizlet.features.infra.models.folders.c cVar : bVarA) {
            int iOrdinal = cVar.b.ordinal();
            if (iOrdinal == 0) {
                str = null;
            } else if (iOrdinal != 1) {
                if (iOrdinal != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                str = null;
            } else {
                str = cVar.c;
            }
            if (str != null) {
                arrayList.add(str);
            }
        }
        d0Var.h(new C4273b0(this.r, arrayList));
    }

    public final void N(Object obj, boolean z) {
        if (kotlin.r.a(obj) != null) {
            Throwable thA = kotlin.r.a(obj);
            boolean z2 = thA instanceof NetworkOfflineError;
            Object x = C4281f0.a;
            if (z2) {
                if (z) {
                    x = C4283g0.a;
                }
            } else if (!(thA instanceof UpdateFolderException) && !(thA instanceof DeleteFolderException)) {
                x = thA instanceof HiddenFolderException ? C4279e0.a : thA instanceof CourseAlreadyInFolderException ? new X(this.I.a) : Y.a;
            }
            this.B.h(x);
        }
    }

    public final void O(EnumC4270a enumC4270a) {
        kotlinx.coroutines.E.A(p0.j(this), null, null, new L(this, enumC4270a, null), 3);
    }

    public final void P(long j, long j2, String str, boolean z) {
        String string = StringsKt.g0(str).toString();
        this.I = new X0(j, j2, string);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new M(this, string, j, j2, z, null), 3);
    }

    public final void Q(boolean z) {
        s0 s0Var;
        Object value;
        Object objA;
        String tagName = this.t;
        com.quizlet.features.folders.logging.e eVar = this.h;
        eVar.getClass();
        Intrinsics.checkNotNullParameter(tagName, "tagName");
        EventLoggerExt.a(eVar.a, "folder_search_clicked", new com.quizlet.eventlogger.features.learnonboarding.c(1, this.r, tagName));
        do {
            s0Var = this.u;
            value = s0Var.getValue();
            objA = (W) value;
            U u = objA instanceof U ? (U) objA : null;
            if (u != null) {
                objA = U.a(u, null, z, 1);
            }
        } while (!s0Var.k(value, objA));
        K();
    }
}
