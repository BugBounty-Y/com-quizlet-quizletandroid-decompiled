package com.braze.ui.inappmessage;

import android.view.View;
import com.google.android.gms.internal.ads.C1756Qb;
import com.perimeterx.mobile_sdk.doctor_app.g;
import com.perimeterx.mobile_sdk.doctor_app.ui.PXDoctorActivity;
import com.quizlet.features.infra.snackbar.k;
import com.quizlet.quizletandroid.ui.common.views.ShareSetButton;
import com.quizlet.quizletandroid.ui.group.classcontent.ClassContentListFragment;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class f implements View.OnClickListener {
    public final /* synthetic */ int a;

    public /* synthetic */ f(int i) {
        this.a = i;
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        com.perimeterx.mobile_sdk.doctor_app.state.d bVar;
        int i = 22;
        switch (this.a) {
            case 0:
                DefaultInAppMessageViewWrapper.createCloseInAppMessageClickListener$lambda$22(view);
                return;
            case 1:
                PXDoctorActivity.a(view);
                return;
            case 2:
                androidx.constraintlayout.core.widgets.analyzer.f fVar = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar);
                com.perimeterx.mobile_sdk.doctor_app.e action = com.perimeterx.mobile_sdk.doctor_app.e.h;
                Intrinsics.checkNotNullParameter(action, "action");
                fVar.d(B.f(new com.perimeterx.mobile_sdk.doctor_app.model.a(action), new com.perimeterx.mobile_sdk.doctor_app.model.a(new com.quizlet.shared.usecase.studiableMetadata.a(i))));
                return;
            case 3:
                androidx.constraintlayout.core.widgets.analyzer.f fVar2 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar2);
                com.perimeterx.mobile_sdk.doctor_app.model.a action2 = new com.perimeterx.mobile_sdk.doctor_app.model.a(new retrofit2.adapter.rxjava3.d(i));
                Intrinsics.checkNotNullParameter(action2, "action");
                fVar2.d(B.f(action2));
                return;
            case 4:
                androidx.constraintlayout.core.widgets.analyzer.f fVar3 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar3);
                if (((com.perimeterx.mobile_sdk.doctor_app.model.c) fVar3.h).g) {
                    androidx.constraintlayout.core.widgets.analyzer.f fVar4 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                    Intrinsics.d(fVar4);
                    com.perimeterx.mobile_sdk.doctor_app.e action3 = com.perimeterx.mobile_sdk.doctor_app.e.k;
                    Intrinsics.checkNotNullParameter(action3, "action");
                    fVar4.a(new com.perimeterx.mobile_sdk.doctor_app.model.a(action3));
                    return;
                }
                androidx.constraintlayout.core.widgets.analyzer.f fVar5 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar5);
                fVar5.k();
                androidx.constraintlayout.core.widgets.analyzer.f fVar6 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar6);
                com.perimeterx.mobile_sdk.doctor_app.model.a action4 = new com.perimeterx.mobile_sdk.doctor_app.model.a(new com.quizlet.shared.usecase.folderstudymaterials.c(i));
                Intrinsics.checkNotNullParameter(action4, "action");
                fVar6.d(B.f(action4));
                return;
            case 5:
                androidx.constraintlayout.core.widgets.analyzer.f fVar7 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar7);
                if (((com.perimeterx.mobile_sdk.doctor_app.model.c) fVar7.h).g) {
                    androidx.constraintlayout.core.widgets.analyzer.f fVar8 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                    Intrinsics.d(fVar8);
                    fVar8.n();
                    return;
                } else {
                    androidx.constraintlayout.core.widgets.analyzer.f fVar9 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                    Intrinsics.d(fVar9);
                    com.perimeterx.mobile_sdk.doctor_app.e action5 = com.perimeterx.mobile_sdk.doctor_app.e.k;
                    Intrinsics.checkNotNullParameter(action5, "action");
                    fVar9.a(new com.perimeterx.mobile_sdk.doctor_app.model.a(action5));
                    return;
                }
            case 6:
                androidx.constraintlayout.core.widgets.analyzer.f fVar10 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar10);
                fVar10.n();
                return;
            case 7:
                androidx.constraintlayout.core.widgets.analyzer.f fVar11 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar11);
                com.perimeterx.mobile_sdk.doctor_app.model.a action6 = new com.perimeterx.mobile_sdk.doctor_app.model.a(new com.perimeterx.mobile_sdk.doctor_app.state.f());
                Intrinsics.checkNotNullParameter(action6, "action");
                fVar11.d(B.f(action6));
                return;
            case 8:
                androidx.constraintlayout.core.widgets.analyzer.f fVar12 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar12);
                com.perimeterx.mobile_sdk.doctor_app.model.a action7 = new com.perimeterx.mobile_sdk.doctor_app.model.a(new com.perimeterx.mobile_sdk.doctor_app.state.f());
                Intrinsics.checkNotNullParameter(action7, "action");
                fVar12.d(B.f(action7));
                return;
            case 9:
                androidx.constraintlayout.core.widgets.analyzer.f fVar13 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar13);
                com.perimeterx.mobile_sdk.doctor_app.f fVar14 = com.perimeterx.mobile_sdk.doctor_app.f.b;
                fVar13.g = fVar14;
                ((com.perimeterx.mobile_sdk.doctor_app.model.d) fVar13.i).g = fVar14;
                androidx.constraintlayout.core.widgets.analyzer.f fVar15 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar15);
                com.perimeterx.mobile_sdk.doctor_app.model.a action8 = new com.perimeterx.mobile_sdk.doctor_app.model.a(new com.quizlet.shared.usecase.folderstudymaterials.d(i));
                Intrinsics.checkNotNullParameter(action8, "action");
                fVar15.d(B.f(action8));
                return;
            case 10:
                androidx.constraintlayout.core.widgets.analyzer.f fVar16 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar16);
                com.perimeterx.mobile_sdk.doctor_app.f fVar17 = com.perimeterx.mobile_sdk.doctor_app.f.c;
                fVar16.g = fVar17;
                ((com.perimeterx.mobile_sdk.doctor_app.model.d) fVar16.i).g = fVar17;
                androidx.constraintlayout.core.widgets.analyzer.f fVar18 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar18);
                com.perimeterx.mobile_sdk.doctor_app.model.a action9 = new com.perimeterx.mobile_sdk.doctor_app.model.a(new com.quizlet.shared.usecase.folderstudymaterials.d(i));
                Intrinsics.checkNotNullParameter(action9, "action");
                fVar18.d(B.f(action9));
                return;
            case 11:
                androidx.constraintlayout.core.widgets.analyzer.f fVar19 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar19);
                fVar19.k();
                return;
            case 12:
                androidx.constraintlayout.core.widgets.analyzer.f fVar20 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar20);
                com.perimeterx.mobile_sdk.doctor_app.e action10 = com.perimeterx.mobile_sdk.doctor_app.e.h;
                Intrinsics.checkNotNullParameter(action10, "action");
                fVar20.d(B.f(new com.perimeterx.mobile_sdk.doctor_app.model.a(action10), new com.perimeterx.mobile_sdk.doctor_app.model.a(new com.quizlet.shared.usecase.studiableMetadata.a(i))));
                return;
            case 13:
                androidx.constraintlayout.core.widgets.analyzer.f fVar21 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar21);
                com.perimeterx.mobile_sdk.doctor_app.e action11 = com.perimeterx.mobile_sdk.doctor_app.e.c;
                Intrinsics.checkNotNullParameter(action11, "action");
                fVar21.a(new com.perimeterx.mobile_sdk.doctor_app.model.a(action11));
                return;
            case 14:
                androidx.constraintlayout.core.widgets.analyzer.f fVar22 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar22);
                g gVar = fVar22.f() ? g.a : fVar22.h() ? g.b : null;
                if (gVar != null) {
                    int iOrdinal = gVar.ordinal();
                    if (iOrdinal == 0) {
                        bVar = new com.perimeterx.mobile_sdk.doctor_app.state.b();
                    } else {
                        if (iOrdinal != 1) {
                            throw new NoWhenBranchMatchedException();
                        }
                        bVar = new com.perimeterx.mobile_sdk.doctor_app.state.g();
                    }
                    androidx.constraintlayout.core.widgets.analyzer.f fVar23 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                    Intrinsics.d(fVar23);
                    com.perimeterx.mobile_sdk.doctor_app.model.a action12 = new com.perimeterx.mobile_sdk.doctor_app.model.a(bVar);
                    Intrinsics.checkNotNullParameter(action12, "action");
                    fVar23.d(B.f(action12));
                    return;
                }
                return;
            case 15:
                androidx.constraintlayout.core.widgets.analyzer.f fVar24 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar24);
                fVar24.n();
                return;
            case 16:
                androidx.constraintlayout.core.widgets.analyzer.f fVar25 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar25);
                com.perimeterx.mobile_sdk.doctor_app.model.a action13 = new com.perimeterx.mobile_sdk.doctor_app.model.a(new com.quizlet.shared.usecase.srs.a(i));
                Intrinsics.checkNotNullParameter(action13, "action");
                fVar25.d(B.f(action13));
                return;
            case 17:
                com.quizlet.features.infra.snackbar.c cVar = k.a;
                return;
            case 18:
                int i2 = ShareSetButton.r;
                timber.log.c.a.e(new C1756Qb("Click listener was not setup correctly: call ShareSetButton#initializeShareClickListener"));
                return;
            default:
                String str = ClassContentListFragment.n;
                return;
        }
    }
}
