package com.quizlet.quizletandroid.ui.studymodes.match.fragment.challenge;

import android.content.res.Resources;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.cardview.widget.CardView;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.data.repository.folderwithcreatorinclass.e;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.features.infra.basestudy.manager.f;
import com.quizlet.features.match.data.I;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.common.ads.G;
import com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g;
import io.reactivex.rxjava3.core.p;
import java.text.DecimalFormat;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.l;
import kotlin.u;

@Metadata
/* loaded from: classes3.dex */
public final class ChallengeDialogFragment extends Hilt_ChallengeDialogFragment {
    public static final String B;
    public final e A = new e(K.a(g.class), new c(this, 0), new c(this, 2), new c(this, 1));
    public com.quizlet.qutils.image.loading.a v;
    public com.onetrust.otpublishers.headless.databinding.d w;
    public final u x;
    public final u y;
    public final u z;

    static {
        Intrinsics.checkNotNullExpressionValue("ChallengeDialogFragment", "getSimpleName(...)");
        B = "ChallengeDialogFragment";
    }

    public ChallengeDialogFragment() {
        final int i = 0;
        this.x = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.challenge.b
            public final /* synthetic */ ChallengeDialogFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                ChallengeDialogFragment challengeDialogFragment = this.b;
                switch (i) {
                    case 0:
                        String str = ChallengeDialogFragment.B;
                        String string = challengeDialogFragment.requireArguments().getString("profileImageUrl");
                        return string == null ? "" : string;
                    case 1:
                        String str2 = ChallengeDialogFragment.B;
                        return challengeDialogFragment.requireArguments().getString("username");
                    default:
                        String str3 = ChallengeDialogFragment.B;
                        return Double.valueOf(challengeDialogFragment.requireArguments().getDouble("scoreInSeconds"));
                }
            }
        });
        final int i2 = 1;
        this.y = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.challenge.b
            public final /* synthetic */ ChallengeDialogFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                ChallengeDialogFragment challengeDialogFragment = this.b;
                switch (i2) {
                    case 0:
                        String str = ChallengeDialogFragment.B;
                        String string = challengeDialogFragment.requireArguments().getString("profileImageUrl");
                        return string == null ? "" : string;
                    case 1:
                        String str2 = ChallengeDialogFragment.B;
                        return challengeDialogFragment.requireArguments().getString("username");
                    default:
                        String str3 = ChallengeDialogFragment.B;
                        return Double.valueOf(challengeDialogFragment.requireArguments().getDouble("scoreInSeconds"));
                }
            }
        });
        final int i3 = 2;
        this.z = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.challenge.b
            public final /* synthetic */ ChallengeDialogFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                ChallengeDialogFragment challengeDialogFragment = this.b;
                switch (i3) {
                    case 0:
                        String str = ChallengeDialogFragment.B;
                        String string = challengeDialogFragment.requireArguments().getString("profileImageUrl");
                        return string == null ? "" : string;
                    case 1:
                        String str2 = ChallengeDialogFragment.B;
                        return challengeDialogFragment.requireArguments().getString("username");
                    default:
                        String str3 = ChallengeDialogFragment.B;
                        return Double.valueOf(challengeDialogFragment.requireArguments().getDouble("scoreInSeconds"));
                }
            }
        });
    }

    public final com.onetrust.otpublishers.headless.databinding.d R() {
        com.onetrust.otpublishers.headless.databinding.d dVar = this.w;
        if (dVar != null) {
            return dVar;
        }
        throw new IllegalArgumentException("Required value was null.");
    }

    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.dialog_challenge, viewGroup, false);
        int i = R.id.bodyText;
        if (((QTextView) AbstractC3375o2.c(R.id.bodyText, viewInflate)) != null) {
            i = R.id.headerText;
            if (((QTextView) AbstractC3375o2.c(R.id.headerText, viewInflate)) != null) {
                i = R.id.headerTimeText;
                QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.headerTimeText, viewInflate);
                if (qTextView != null) {
                    i = R.id.imageView;
                    if (((ImageView) AbstractC3375o2.c(R.id.imageView, viewInflate)) != null) {
                        i = R.id.imageView2;
                        if (((ImageView) AbstractC3375o2.c(R.id.imageView2, viewInflate)) != null) {
                            i = R.id.matchChallengeNegativeCta;
                            QButton qButton = (QButton) AbstractC3375o2.c(R.id.matchChallengeNegativeCta, viewInflate);
                            if (qButton != null) {
                                i = R.id.matchChallengePositiveCta;
                                QButton qButton2 = (QButton) AbstractC3375o2.c(R.id.matchChallengePositiveCta, viewInflate);
                                if (qButton2 != null) {
                                    i = R.id.randomProfilePicture;
                                    if (((CardView) AbstractC3375o2.c(R.id.randomProfilePicture, viewInflate)) != null) {
                                        i = R.id.randomProfilePictureImage;
                                        if (((ImageView) AbstractC3375o2.c(R.id.randomProfilePictureImage, viewInflate)) != null) {
                                            i = R.id.randomTime;
                                            if (((QTextView) AbstractC3375o2.c(R.id.randomTime, viewInflate)) != null) {
                                                i = R.id.randomUsername;
                                                if (((QTextView) AbstractC3375o2.c(R.id.randomUsername, viewInflate)) != null) {
                                                    i = R.id.userProfilePicture;
                                                    if (((CardView) AbstractC3375o2.c(R.id.userProfilePicture, viewInflate)) != null) {
                                                        i = R.id.userProfilePictureImage;
                                                        ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.userProfilePictureImage, viewInflate);
                                                        if (imageView != null) {
                                                            i = R.id.userTime;
                                                            QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.userTime, viewInflate);
                                                            if (qTextView2 != null) {
                                                                i = R.id.usernameView;
                                                                QTextView qTextView3 = (QTextView) AbstractC3375o2.c(R.id.usernameView, viewInflate);
                                                                if (qTextView3 != null) {
                                                                    i = R.id.vsSymbol;
                                                                    if (((TextView) AbstractC3375o2.c(R.id.vsSymbol, viewInflate)) != null) {
                                                                        ScrollView scrollView = (ScrollView) viewInflate;
                                                                        this.w = new com.onetrust.otpublishers.headless.databinding.d(scrollView, qTextView, qButton, qButton2, imageView, qTextView2, qTextView3);
                                                                        Intrinsics.checkNotNullExpressionValue(scrollView, "getRoot(...)");
                                                                        return scrollView;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        super.onDestroyView();
        this.w = null;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) throws Resources.NotFoundException {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        com.onetrust.otpublishers.headless.databinding.d dVarR = R();
        ((QTextView) dVarR.h).setText((String) this.y.getValue());
        DecimalFormat decimalFormat = new DecimalFormat("0.0");
        Resources resources = getResources();
        u uVar = this.z;
        String quantityString = resources.getQuantityString(R.plurals.match_challenge_time_header, (int) ((Number) uVar.getValue()).doubleValue(), decimalFormat.format(((Number) uVar.getValue()).doubleValue()));
        Intrinsics.checkNotNullExpressionValue(quantityString, "getQuantityString(...)");
        ((QTextView) R().g).setText(quantityString);
        ((QTextView) R().c).setText(quantityString);
        com.quizlet.qutils.image.loading.a aVar = this.v;
        if (aVar == null) {
            Intrinsics.m("imageLoader");
            throw null;
        }
        com.quizlet.data.repository.widget.b bVarP = ((com.quizlet.quizletandroid.ui.common.images.loading.glide.a) aVar).a(requireContext()).p((String) this.x.getValue());
        bVarP.d();
        bVarP.o((ImageView) R().d);
        com.onetrust.otpublishers.headless.databinding.d dVarR2 = R();
        final int i = 0;
        ((QButton) dVarR2.e).setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.challenge.a
            public final /* synthetic */ ChallengeDialogFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                ChallengeDialogFragment challengeDialogFragment = this.b;
                switch (i) {
                    case 0:
                        String str = ChallengeDialogFragment.B;
                        challengeDialogFragment.H(false, false);
                        break;
                    default:
                        g gVar = (g) challengeDialogFragment.A.getValue();
                        com.quizlet.quizletandroid.ui.studymodes.match.managers.a aVar2 = gVar.k;
                        f fVar = aVar2.a;
                        DBStudySet dBStudySetE = fVar.e();
                        String title = dBStudySetE != null ? dBStudySetE.getTitle() : null;
                        String webUrl = dBStudySetE != null ? dBStudySetE.getWebUrl() : null;
                        io.reactivex.rxjava3.internal.observers.e eVarB = B7.b((dBStudySetE == null || title == null || webUrl == null) ? p.f(new I(null)) : fVar.f().e(new com.quizlet.data.repository.user.e(aVar2, dBStudySetE, webUrl, title, 7)), io.reactivex.rxjava3.kotlin.c.b, new G(gVar, 22));
                        Intrinsics.checkNotNullParameter(eVarB, "<this>");
                        gVar.A(eVarB);
                        challengeDialogFragment.H(false, false);
                        break;
                }
            }
        });
        com.onetrust.otpublishers.headless.databinding.d dVarR3 = R();
        final int i2 = 1;
        ((QButton) dVarR3.f).setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.challenge.a
            public final /* synthetic */ ChallengeDialogFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                ChallengeDialogFragment challengeDialogFragment = this.b;
                switch (i2) {
                    case 0:
                        String str = ChallengeDialogFragment.B;
                        challengeDialogFragment.H(false, false);
                        break;
                    default:
                        g gVar = (g) challengeDialogFragment.A.getValue();
                        com.quizlet.quizletandroid.ui.studymodes.match.managers.a aVar2 = gVar.k;
                        f fVar = aVar2.a;
                        DBStudySet dBStudySetE = fVar.e();
                        String title = dBStudySetE != null ? dBStudySetE.getTitle() : null;
                        String webUrl = dBStudySetE != null ? dBStudySetE.getWebUrl() : null;
                        io.reactivex.rxjava3.internal.observers.e eVarB = B7.b((dBStudySetE == null || title == null || webUrl == null) ? p.f(new I(null)) : fVar.f().e(new com.quizlet.data.repository.user.e(aVar2, dBStudySetE, webUrl, title, 7)), io.reactivex.rxjava3.kotlin.c.b, new G(gVar, 22));
                        Intrinsics.checkNotNullParameter(eVarB, "<this>");
                        gVar.A(eVarB);
                        challengeDialogFragment.H(false, false);
                        break;
                }
            }
        });
    }
}
