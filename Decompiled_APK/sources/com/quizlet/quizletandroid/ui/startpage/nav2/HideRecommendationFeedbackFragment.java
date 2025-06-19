package com.quizlet.quizletandroid.ui.startpage.nav2;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_barcode.D6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4620y;
import com.quizlet.quizletandroid.ui.base.BaseContentBindingConvertableModalDialogFragment;
import com.quizlet.quizletandroid.ui.common.views.SimpleTextCardView;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class HideRecommendationFeedbackFragment extends BaseContentBindingConvertableModalDialogFragment<C4620y> {
    public static final String B;
    public Y A;
    public com.onetrust.otpublishers.headless.UI.viewmodel.c z;

    static {
        Intrinsics.checkNotNullExpressionValue("HideRecommendationFeedbackFragment", "getSimpleName(...)");
        B = "HideRecommendationFeedbackFragment";
    }

    @Override // com.quizlet.quizletandroid.ui.base.BaseContentBindingConvertableModalDialogFragment
    public final androidx.viewbinding.a S(LayoutInflater inflater, FrameLayout frameLayout) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_hide_recommendation_feedback, (ViewGroup) frameLayout, false);
        int i = R.id.cancelReasonsButton;
        QButton qButton = (QButton) AbstractC3375o2.c(R.id.cancelReasonsButton, viewInflate);
        if (qButton != null) {
            i = R.id.reasonFourCard;
            SimpleTextCardView simpleTextCardView = (SimpleTextCardView) AbstractC3375o2.c(R.id.reasonFourCard, viewInflate);
            if (simpleTextCardView != null) {
                i = R.id.reasonOneCard;
                SimpleTextCardView simpleTextCardView2 = (SimpleTextCardView) AbstractC3375o2.c(R.id.reasonOneCard, viewInflate);
                if (simpleTextCardView2 != null) {
                    i = R.id.reasonThreeCard;
                    SimpleTextCardView simpleTextCardView3 = (SimpleTextCardView) AbstractC3375o2.c(R.id.reasonThreeCard, viewInflate);
                    if (simpleTextCardView3 != null) {
                        i = R.id.reasonTwoCard;
                        SimpleTextCardView simpleTextCardView4 = (SimpleTextCardView) AbstractC3375o2.c(R.id.reasonTwoCard, viewInflate);
                        if (simpleTextCardView4 != null) {
                            i = R.id.title;
                            if (((TextView) AbstractC3375o2.c(R.id.title, viewInflate)) != null) {
                                C4620y c4620y = new C4620y((ConstraintLayout) viewInflate, qButton, simpleTextCardView, simpleTextCardView2, simpleTextCardView3, simpleTextCardView4);
                                Intrinsics.checkNotNullExpressionValue(c4620y, "inflate(...)");
                                return c4620y;
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final void T(com.quizlet.generated.enums.F reason) {
        Y y = this.A;
        if (y == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        long j = requireArguments().getLong("setID", 0L);
        int i = requireArguments().getInt("recsSectionNumber", -1);
        Intrinsics.checkNotNullParameter(reason, "reason");
        kotlinx.coroutines.E.A(p0.j(y), null, null, new V(i, y, j, reason, null), 3);
        H(false, false);
    }

    @Override // androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        androidx.viewbinding.a aVar = this.y;
        if (aVar == null) {
            throw new IllegalStateException("View binding is only valid between onCreateView and onDestroyView");
        }
        C4620y c4620y = (C4620y) aVar;
        final int i = 0;
        c4620y.d.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.startpage.nav2.a
            public final /* synthetic */ HideRecommendationFeedbackFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                HideRecommendationFeedbackFragment hideRecommendationFeedbackFragment = this.b;
                switch (i) {
                    case 0:
                        String str = HideRecommendationFeedbackFragment.B;
                        hideRecommendationFeedbackFragment.T(com.quizlet.generated.enums.F.WRONG_CONTENT);
                        break;
                    case 1:
                        String str2 = HideRecommendationFeedbackFragment.B;
                        hideRecommendationFeedbackFragment.T(com.quizlet.generated.enums.F.WRONG_TIMING);
                        break;
                    case 2:
                        String str3 = HideRecommendationFeedbackFragment.B;
                        hideRecommendationFeedbackFragment.T(com.quizlet.generated.enums.F.BAD_QUALITY);
                        break;
                    case 3:
                        String str4 = HideRecommendationFeedbackFragment.B;
                        hideRecommendationFeedbackFragment.T(com.quizlet.generated.enums.F.OTHER);
                        break;
                    default:
                        String str5 = HideRecommendationFeedbackFragment.B;
                        hideRecommendationFeedbackFragment.H(false, false);
                        break;
                }
            }
        });
        final int i2 = 1;
        c4620y.f.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.startpage.nav2.a
            public final /* synthetic */ HideRecommendationFeedbackFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                HideRecommendationFeedbackFragment hideRecommendationFeedbackFragment = this.b;
                switch (i2) {
                    case 0:
                        String str = HideRecommendationFeedbackFragment.B;
                        hideRecommendationFeedbackFragment.T(com.quizlet.generated.enums.F.WRONG_CONTENT);
                        break;
                    case 1:
                        String str2 = HideRecommendationFeedbackFragment.B;
                        hideRecommendationFeedbackFragment.T(com.quizlet.generated.enums.F.WRONG_TIMING);
                        break;
                    case 2:
                        String str3 = HideRecommendationFeedbackFragment.B;
                        hideRecommendationFeedbackFragment.T(com.quizlet.generated.enums.F.BAD_QUALITY);
                        break;
                    case 3:
                        String str4 = HideRecommendationFeedbackFragment.B;
                        hideRecommendationFeedbackFragment.T(com.quizlet.generated.enums.F.OTHER);
                        break;
                    default:
                        String str5 = HideRecommendationFeedbackFragment.B;
                        hideRecommendationFeedbackFragment.H(false, false);
                        break;
                }
            }
        });
        final int i3 = 2;
        c4620y.e.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.startpage.nav2.a
            public final /* synthetic */ HideRecommendationFeedbackFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                HideRecommendationFeedbackFragment hideRecommendationFeedbackFragment = this.b;
                switch (i3) {
                    case 0:
                        String str = HideRecommendationFeedbackFragment.B;
                        hideRecommendationFeedbackFragment.T(com.quizlet.generated.enums.F.WRONG_CONTENT);
                        break;
                    case 1:
                        String str2 = HideRecommendationFeedbackFragment.B;
                        hideRecommendationFeedbackFragment.T(com.quizlet.generated.enums.F.WRONG_TIMING);
                        break;
                    case 2:
                        String str3 = HideRecommendationFeedbackFragment.B;
                        hideRecommendationFeedbackFragment.T(com.quizlet.generated.enums.F.BAD_QUALITY);
                        break;
                    case 3:
                        String str4 = HideRecommendationFeedbackFragment.B;
                        hideRecommendationFeedbackFragment.T(com.quizlet.generated.enums.F.OTHER);
                        break;
                    default:
                        String str5 = HideRecommendationFeedbackFragment.B;
                        hideRecommendationFeedbackFragment.H(false, false);
                        break;
                }
            }
        });
        final int i4 = 3;
        c4620y.c.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.startpage.nav2.a
            public final /* synthetic */ HideRecommendationFeedbackFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                HideRecommendationFeedbackFragment hideRecommendationFeedbackFragment = this.b;
                switch (i4) {
                    case 0:
                        String str = HideRecommendationFeedbackFragment.B;
                        hideRecommendationFeedbackFragment.T(com.quizlet.generated.enums.F.WRONG_CONTENT);
                        break;
                    case 1:
                        String str2 = HideRecommendationFeedbackFragment.B;
                        hideRecommendationFeedbackFragment.T(com.quizlet.generated.enums.F.WRONG_TIMING);
                        break;
                    case 2:
                        String str3 = HideRecommendationFeedbackFragment.B;
                        hideRecommendationFeedbackFragment.T(com.quizlet.generated.enums.F.BAD_QUALITY);
                        break;
                    case 3:
                        String str4 = HideRecommendationFeedbackFragment.B;
                        hideRecommendationFeedbackFragment.T(com.quizlet.generated.enums.F.OTHER);
                        break;
                    default:
                        String str5 = HideRecommendationFeedbackFragment.B;
                        hideRecommendationFeedbackFragment.H(false, false);
                        break;
                }
            }
        });
        final int i5 = 4;
        c4620y.b.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.startpage.nav2.a
            public final /* synthetic */ HideRecommendationFeedbackFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                HideRecommendationFeedbackFragment hideRecommendationFeedbackFragment = this.b;
                switch (i5) {
                    case 0:
                        String str = HideRecommendationFeedbackFragment.B;
                        hideRecommendationFeedbackFragment.T(com.quizlet.generated.enums.F.WRONG_CONTENT);
                        break;
                    case 1:
                        String str2 = HideRecommendationFeedbackFragment.B;
                        hideRecommendationFeedbackFragment.T(com.quizlet.generated.enums.F.WRONG_TIMING);
                        break;
                    case 2:
                        String str3 = HideRecommendationFeedbackFragment.B;
                        hideRecommendationFeedbackFragment.T(com.quizlet.generated.enums.F.BAD_QUALITY);
                        break;
                    case 3:
                        String str4 = HideRecommendationFeedbackFragment.B;
                        hideRecommendationFeedbackFragment.T(com.quizlet.generated.enums.F.OTHER);
                        break;
                    default:
                        String str5 = HideRecommendationFeedbackFragment.B;
                        hideRecommendationFeedbackFragment.H(false, false);
                        break;
                }
            }
        });
        androidx.fragment.app.I iRequireActivity = requireActivity();
        Intrinsics.checkNotNullExpressionValue(iRequireActivity, "requireActivity(...)");
        com.onetrust.otpublishers.headless.UI.viewmodel.c cVar = this.z;
        if (cVar != null) {
            this.A = (Y) D6.f(iRequireActivity, cVar).a(Y.class);
        } else {
            Intrinsics.m("viewModelFactory");
            throw null;
        }
    }
}
