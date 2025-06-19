package com.quizlet.quizletandroid.ui.startpage.nav2;

import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_barcode.D6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.eventlogger.features.study.StudyFunnelEventLogger;
import com.quizlet.generated.enums.EnumC4519s1;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.base.BaseContentBindingConvertableModalDialogFragment;
import com.quizlet.quizletandroid.ui.common.views.SimpleImageWithTextCardView;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4741j;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4742k;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4745n;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.OnDismissFragment;
import kotlin.Metadata;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class RecommendationsActionOptionsFragment extends BaseContentBindingConvertableModalDialogFragment<com.quizlet.quizletandroid.databinding.E> {
    public static final String D;
    public com.onetrust.otpublishers.headless.UI.viewmodel.c A;
    public com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.N B;
    public com.quizlet.features.infra.snackbar.viewmodel.a C;
    public com.quizlet.quizletandroid.util.a z;

    static {
        Intrinsics.checkNotNullExpressionValue("RecommendationsActionOptionsFragment", "getSimpleName(...)");
        D = "RecommendationsActionOptionsFragment";
    }

    @Override // com.quizlet.quizletandroid.ui.base.BaseContentBindingConvertableModalDialogFragment
    public final androidx.viewbinding.a S(LayoutInflater inflater, FrameLayout frameLayout) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_recommendations_action_options, (ViewGroup) frameLayout, false);
        int i = R.id.cancelActionOptionsButton;
        QButton qButton = (QButton) AbstractC3375o2.c(R.id.cancelActionOptionsButton, viewInflate);
        if (qButton != null) {
            i = R.id.notRelevantCard;
            SimpleImageWithTextCardView simpleImageWithTextCardView = (SimpleImageWithTextCardView) AbstractC3375o2.c(R.id.notRelevantCard, viewInflate);
            if (simpleImageWithTextCardView != null) {
                i = R.id.saveToClassCard;
                SimpleImageWithTextCardView simpleImageWithTextCardView2 = (SimpleImageWithTextCardView) AbstractC3375o2.c(R.id.saveToClassCard, viewInflate);
                if (simpleImageWithTextCardView2 != null) {
                    i = R.id.saveToFolderCard;
                    SimpleImageWithTextCardView simpleImageWithTextCardView3 = (SimpleImageWithTextCardView) AbstractC3375o2.c(R.id.saveToFolderCard, viewInflate);
                    if (simpleImageWithTextCardView3 != null) {
                        i = R.id.title;
                        if (((TextView) AbstractC3375o2.c(R.id.title, viewInflate)) != null) {
                            com.quizlet.quizletandroid.databinding.E e = new com.quizlet.quizletandroid.databinding.E((ConstraintLayout) viewInflate, qButton, simpleImageWithTextCardView, simpleImageWithTextCardView2, simpleImageWithTextCardView3);
                            Intrinsics.checkNotNullExpressionValue(e, "inflate(...)");
                            return e;
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // androidx.fragment.app.Fragment
    public final void onActivityResult(int i, int i2, Intent intent) throws Exception {
        super.onActivityResult(i, i2, intent);
        if (i != 216) {
            if (i == 222 && i2 == -1) {
                com.quizlet.features.infra.snackbar.d dVar = com.quizlet.features.infra.snackbar.k.b;
                Object[] args = new Object[0];
                Intrinsics.checkNotNullParameter(args, "args");
                com.quizlet.features.infra.snackbar.l lVar = new com.quizlet.features.infra.snackbar.l(dVar, 0, new com.quizlet.qutils.string.f(R.string.add_set_classes_complete, C4933y.P(args)), null, null, 120);
                com.quizlet.features.infra.snackbar.viewmodel.a aVar = this.C;
                if (aVar == null) {
                    Intrinsics.m("snackbarViewModel");
                    throw null;
                }
                ((com.quizlet.features.infra.snackbar.viewmodel.c) aVar).A(lVar);
            }
        } else if (i2 == -1) {
            com.quizlet.quizletandroid.util.a aVar2 = this.z;
            if (aVar2 == null) {
                Intrinsics.m("addSetToClassManager");
                throw null;
            }
            androidx.fragment.app.I iRequireActivity = requireActivity();
            Intrinsics.checkNotNullExpressionValue(iRequireActivity, "requireActivity(...)");
            Intrinsics.d(intent);
            aVar2.a(iRequireActivity, intent, new a0(this, 0));
        }
        H(false, false);
    }

    @Override // androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        com.onetrust.otpublishers.headless.UI.viewmodel.c cVar = this.A;
        if (cVar == null) {
            Intrinsics.m("viewModelFactory");
            throw null;
        }
        this.B = (com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.N) D6.f(this, cVar).a(com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.N.class);
        androidx.fragment.app.I iRequireActivity = requireActivity();
        Intrinsics.checkNotNullExpressionValue(iRequireActivity, "requireActivity(...)");
        this.C = (com.quizlet.features.infra.snackbar.viewmodel.a) D6.f(iRequireActivity, null).a(com.quizlet.features.infra.snackbar.viewmodel.c.class);
        androidx.viewbinding.a aVar = this.y;
        if (aVar == null) {
            throw new IllegalStateException("View binding is only valid between onCreateView and onDestroyView");
        }
        com.quizlet.quizletandroid.databinding.E e = (com.quizlet.quizletandroid.databinding.E) aVar;
        final int i = 0;
        e.d.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.startpage.nav2.Z
            public final /* synthetic */ RecommendationsActionOptionsFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                switch (i) {
                    case 0:
                        com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.N n = this.b.B;
                        if (n == null) {
                            Intrinsics.m("viewModel");
                            throw null;
                        }
                        com.quizlet.features.infra.basestudy.manager.d dVar = n.c;
                        long j = n.d;
                        com.quizlet.features.infra.basestudy.manager.c cVarC = dVar.c(j);
                        if (cVarC != null) {
                            EnumC4519s1 enumC4519s1 = EnumC4519s1.CLICK_SAVE_TO_CLASS;
                            com.quizlet.features.infra.basestudy.manager.b bVar = cVarC.b;
                            StudyFunnelEventLogger.a(dVar.a, enumC4519s1, Long.valueOf(j), 1, cVarC.a, bVar.d, bVar.e, bVar.f, bVar.g, null, null, null, null, 3840);
                        }
                        n.f.j(new C4741j(j));
                        return;
                    case 1:
                        com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.N n2 = this.b.B;
                        if (n2 == null) {
                            Intrinsics.m("viewModel");
                            throw null;
                        }
                        com.quizlet.features.infra.basestudy.manager.d dVar2 = n2.c;
                        long j2 = n2.d;
                        com.quizlet.features.infra.basestudy.manager.c cVarC2 = dVar2.c(j2);
                        if (cVarC2 != null) {
                            EnumC4519s1 enumC4519s12 = EnumC4519s1.CLICK_SAVE_TO_FOLDER;
                            com.quizlet.features.infra.basestudy.manager.b bVar2 = cVarC2.b;
                            StudyFunnelEventLogger.a(dVar2.a, enumC4519s12, Long.valueOf(j2), 1, cVarC2.a, bVar2.d, bVar2.e, bVar2.f, bVar2.g, null, null, null, null, 3840);
                        }
                        n2.f.j(new C4742k(j2));
                        return;
                    case 2:
                        com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.N n3 = this.b.B;
                        if (n3 == null) {
                            Intrinsics.m("viewModel");
                            throw null;
                        }
                        com.quizlet.features.infra.basestudy.manager.d dVar3 = n3.c;
                        long j3 = n3.d;
                        com.quizlet.features.infra.basestudy.manager.c cVarC3 = dVar3.c(j3);
                        if (cVarC3 != null) {
                            EnumC4519s1 enumC4519s13 = EnumC4519s1.CLICK_HIDE_THIS_SET;
                            com.quizlet.features.infra.basestudy.manager.b bVar3 = cVarC3.b;
                            StudyFunnelEventLogger.a(dVar3.a, enumC4519s13, Long.valueOf(j3), 1, cVarC3.a, bVar3.d, bVar3.e, bVar3.f, bVar3.g, null, null, null, null, 3840);
                        }
                        int i2 = n3.e;
                        n3.f.j(new C4745n(j3, i2 != -1 ? Integer.valueOf(i2) : null));
                        return;
                    default:
                        com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.N n4 = this.b.B;
                        if (n4 != null) {
                            n4.f.j(OnDismissFragment.a);
                            return;
                        } else {
                            Intrinsics.m("viewModel");
                            throw null;
                        }
                }
            }
        });
        final int i2 = 1;
        e.e.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.startpage.nav2.Z
            public final /* synthetic */ RecommendationsActionOptionsFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                switch (i2) {
                    case 0:
                        com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.N n = this.b.B;
                        if (n == null) {
                            Intrinsics.m("viewModel");
                            throw null;
                        }
                        com.quizlet.features.infra.basestudy.manager.d dVar = n.c;
                        long j = n.d;
                        com.quizlet.features.infra.basestudy.manager.c cVarC = dVar.c(j);
                        if (cVarC != null) {
                            EnumC4519s1 enumC4519s1 = EnumC4519s1.CLICK_SAVE_TO_CLASS;
                            com.quizlet.features.infra.basestudy.manager.b bVar = cVarC.b;
                            StudyFunnelEventLogger.a(dVar.a, enumC4519s1, Long.valueOf(j), 1, cVarC.a, bVar.d, bVar.e, bVar.f, bVar.g, null, null, null, null, 3840);
                        }
                        n.f.j(new C4741j(j));
                        return;
                    case 1:
                        com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.N n2 = this.b.B;
                        if (n2 == null) {
                            Intrinsics.m("viewModel");
                            throw null;
                        }
                        com.quizlet.features.infra.basestudy.manager.d dVar2 = n2.c;
                        long j2 = n2.d;
                        com.quizlet.features.infra.basestudy.manager.c cVarC2 = dVar2.c(j2);
                        if (cVarC2 != null) {
                            EnumC4519s1 enumC4519s12 = EnumC4519s1.CLICK_SAVE_TO_FOLDER;
                            com.quizlet.features.infra.basestudy.manager.b bVar2 = cVarC2.b;
                            StudyFunnelEventLogger.a(dVar2.a, enumC4519s12, Long.valueOf(j2), 1, cVarC2.a, bVar2.d, bVar2.e, bVar2.f, bVar2.g, null, null, null, null, 3840);
                        }
                        n2.f.j(new C4742k(j2));
                        return;
                    case 2:
                        com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.N n3 = this.b.B;
                        if (n3 == null) {
                            Intrinsics.m("viewModel");
                            throw null;
                        }
                        com.quizlet.features.infra.basestudy.manager.d dVar3 = n3.c;
                        long j3 = n3.d;
                        com.quizlet.features.infra.basestudy.manager.c cVarC3 = dVar3.c(j3);
                        if (cVarC3 != null) {
                            EnumC4519s1 enumC4519s13 = EnumC4519s1.CLICK_HIDE_THIS_SET;
                            com.quizlet.features.infra.basestudy.manager.b bVar3 = cVarC3.b;
                            StudyFunnelEventLogger.a(dVar3.a, enumC4519s13, Long.valueOf(j3), 1, cVarC3.a, bVar3.d, bVar3.e, bVar3.f, bVar3.g, null, null, null, null, 3840);
                        }
                        int i22 = n3.e;
                        n3.f.j(new C4745n(j3, i22 != -1 ? Integer.valueOf(i22) : null));
                        return;
                    default:
                        com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.N n4 = this.b.B;
                        if (n4 != null) {
                            n4.f.j(OnDismissFragment.a);
                            return;
                        } else {
                            Intrinsics.m("viewModel");
                            throw null;
                        }
                }
            }
        });
        final int i3 = 2;
        e.c.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.startpage.nav2.Z
            public final /* synthetic */ RecommendationsActionOptionsFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                switch (i3) {
                    case 0:
                        com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.N n = this.b.B;
                        if (n == null) {
                            Intrinsics.m("viewModel");
                            throw null;
                        }
                        com.quizlet.features.infra.basestudy.manager.d dVar = n.c;
                        long j = n.d;
                        com.quizlet.features.infra.basestudy.manager.c cVarC = dVar.c(j);
                        if (cVarC != null) {
                            EnumC4519s1 enumC4519s1 = EnumC4519s1.CLICK_SAVE_TO_CLASS;
                            com.quizlet.features.infra.basestudy.manager.b bVar = cVarC.b;
                            StudyFunnelEventLogger.a(dVar.a, enumC4519s1, Long.valueOf(j), 1, cVarC.a, bVar.d, bVar.e, bVar.f, bVar.g, null, null, null, null, 3840);
                        }
                        n.f.j(new C4741j(j));
                        return;
                    case 1:
                        com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.N n2 = this.b.B;
                        if (n2 == null) {
                            Intrinsics.m("viewModel");
                            throw null;
                        }
                        com.quizlet.features.infra.basestudy.manager.d dVar2 = n2.c;
                        long j2 = n2.d;
                        com.quizlet.features.infra.basestudy.manager.c cVarC2 = dVar2.c(j2);
                        if (cVarC2 != null) {
                            EnumC4519s1 enumC4519s12 = EnumC4519s1.CLICK_SAVE_TO_FOLDER;
                            com.quizlet.features.infra.basestudy.manager.b bVar2 = cVarC2.b;
                            StudyFunnelEventLogger.a(dVar2.a, enumC4519s12, Long.valueOf(j2), 1, cVarC2.a, bVar2.d, bVar2.e, bVar2.f, bVar2.g, null, null, null, null, 3840);
                        }
                        n2.f.j(new C4742k(j2));
                        return;
                    case 2:
                        com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.N n3 = this.b.B;
                        if (n3 == null) {
                            Intrinsics.m("viewModel");
                            throw null;
                        }
                        com.quizlet.features.infra.basestudy.manager.d dVar3 = n3.c;
                        long j3 = n3.d;
                        com.quizlet.features.infra.basestudy.manager.c cVarC3 = dVar3.c(j3);
                        if (cVarC3 != null) {
                            EnumC4519s1 enumC4519s13 = EnumC4519s1.CLICK_HIDE_THIS_SET;
                            com.quizlet.features.infra.basestudy.manager.b bVar3 = cVarC3.b;
                            StudyFunnelEventLogger.a(dVar3.a, enumC4519s13, Long.valueOf(j3), 1, cVarC3.a, bVar3.d, bVar3.e, bVar3.f, bVar3.g, null, null, null, null, 3840);
                        }
                        int i22 = n3.e;
                        n3.f.j(new C4745n(j3, i22 != -1 ? Integer.valueOf(i22) : null));
                        return;
                    default:
                        com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.N n4 = this.b.B;
                        if (n4 != null) {
                            n4.f.j(OnDismissFragment.a);
                            return;
                        } else {
                            Intrinsics.m("viewModel");
                            throw null;
                        }
                }
            }
        });
        final int i4 = 3;
        e.b.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.startpage.nav2.Z
            public final /* synthetic */ RecommendationsActionOptionsFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                switch (i4) {
                    case 0:
                        com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.N n = this.b.B;
                        if (n == null) {
                            Intrinsics.m("viewModel");
                            throw null;
                        }
                        com.quizlet.features.infra.basestudy.manager.d dVar = n.c;
                        long j = n.d;
                        com.quizlet.features.infra.basestudy.manager.c cVarC = dVar.c(j);
                        if (cVarC != null) {
                            EnumC4519s1 enumC4519s1 = EnumC4519s1.CLICK_SAVE_TO_CLASS;
                            com.quizlet.features.infra.basestudy.manager.b bVar = cVarC.b;
                            StudyFunnelEventLogger.a(dVar.a, enumC4519s1, Long.valueOf(j), 1, cVarC.a, bVar.d, bVar.e, bVar.f, bVar.g, null, null, null, null, 3840);
                        }
                        n.f.j(new C4741j(j));
                        return;
                    case 1:
                        com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.N n2 = this.b.B;
                        if (n2 == null) {
                            Intrinsics.m("viewModel");
                            throw null;
                        }
                        com.quizlet.features.infra.basestudy.manager.d dVar2 = n2.c;
                        long j2 = n2.d;
                        com.quizlet.features.infra.basestudy.manager.c cVarC2 = dVar2.c(j2);
                        if (cVarC2 != null) {
                            EnumC4519s1 enumC4519s12 = EnumC4519s1.CLICK_SAVE_TO_FOLDER;
                            com.quizlet.features.infra.basestudy.manager.b bVar2 = cVarC2.b;
                            StudyFunnelEventLogger.a(dVar2.a, enumC4519s12, Long.valueOf(j2), 1, cVarC2.a, bVar2.d, bVar2.e, bVar2.f, bVar2.g, null, null, null, null, 3840);
                        }
                        n2.f.j(new C4742k(j2));
                        return;
                    case 2:
                        com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.N n3 = this.b.B;
                        if (n3 == null) {
                            Intrinsics.m("viewModel");
                            throw null;
                        }
                        com.quizlet.features.infra.basestudy.manager.d dVar3 = n3.c;
                        long j3 = n3.d;
                        com.quizlet.features.infra.basestudy.manager.c cVarC3 = dVar3.c(j3);
                        if (cVarC3 != null) {
                            EnumC4519s1 enumC4519s13 = EnumC4519s1.CLICK_HIDE_THIS_SET;
                            com.quizlet.features.infra.basestudy.manager.b bVar3 = cVarC3.b;
                            StudyFunnelEventLogger.a(dVar3.a, enumC4519s13, Long.valueOf(j3), 1, cVarC3.a, bVar3.d, bVar3.e, bVar3.f, bVar3.g, null, null, null, null, 3840);
                        }
                        int i22 = n3.e;
                        n3.f.j(new C4745n(j3, i22 != -1 ? Integer.valueOf(i22) : null));
                        return;
                    default:
                        com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.N n4 = this.b.B;
                        if (n4 != null) {
                            n4.f.j(OnDismissFragment.a);
                            return;
                        } else {
                            Intrinsics.m("viewModel");
                            throw null;
                        }
                }
            }
        });
        com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.N n = this.B;
        if (n == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        n.f.f(this, new com.quizlet.ads.ui.fragments.c(new a0(this, 1)));
    }
}
