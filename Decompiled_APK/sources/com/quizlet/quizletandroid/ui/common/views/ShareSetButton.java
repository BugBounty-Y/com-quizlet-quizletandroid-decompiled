package com.quizlet.quizletandroid.ui.common.views;

import android.content.Context;
import android.content.res.Resources;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.braze.ui.inappmessage.f;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.views.StatefulTintImageView;
import com.quizlet.utm.a;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class ShareSetButton extends ConstraintLayout {
    public static final /* synthetic */ int r = 0;
    public final com.onetrust.otpublishers.headless.databinding.b q;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public ShareSetButton(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    private final StatefulTintImageView getShareImage() {
        StatefulTintImageView shareImage = (StatefulTintImageView) this.q.c;
        Intrinsics.checkNotNullExpressionValue(shareImage, "shareImage");
        return shareImage;
    }

    private final QTextView getShareText() {
        QTextView shareText = (QTextView) this.q.d;
        Intrinsics.checkNotNullExpressionValue(shareText, "shareText");
        return shareText;
    }

    public static void p(final ShareSetButton shareSetButton, final com.quizlet.features.infra.basestudy.data.models.shareset.a shareStatus, final DBStudySet set, final long j) {
        Intrinsics.checkNotNullParameter(shareStatus, "shareStatus");
        Intrinsics.checkNotNullParameter(set, "set");
        Intrinsics.checkNotNullParameter("match", "studyModeUrlFragment");
        final String title = set.getTitle();
        if (shareStatus == com.quizlet.features.infra.basestudy.data.models.shareset.a.d || title == null) {
            super.setVisibility(8);
        } else {
            super.setVisibility(0);
            super.setOnClickListener(new View.OnClickListener() { // from class: com.quizlet.quizletandroid.ui.common.views.e
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) throws Resources.NotFoundException {
                    int i = ShareSetButton.r;
                    ShareSetButton shareSetButton2 = this.a;
                    Context context = shareSetButton2.getContext();
                    Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
                    DBStudySet dBStudySet = set;
                    shareSetButton2.getContext().startActivity(new com.quizlet.features.setpage.utils.links.b(context, dBStudySet.getSetId(), dBStudySet.getWebUrl(), title, new a.C0023a(new a.c(com.quizlet.utm.campaigns.b.MATCH_COMPLETE_SHARE_WITHOUT_SCORE, com.quizlet.utm.mediums.b.SHARE_LINK, com.quizlet.utm.sources.b.SHARE_SHEET_ANDROID), Long.valueOf(j)), "match", null).b(shareStatus));
                }
            });
        }
    }

    public final void setImageResource(int i) {
        getShareImage().setImageResource(i);
    }

    @Override // android.view.View
    public void setOnClickListener(View.OnClickListener onClickListener) {
    }

    public final void setText(int i) {
        getShareText().setText(i);
    }

    @Override // android.view.View
    public void setVisibility(int i) {
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public ShareSetButton(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public ShareSetButton(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0);
        View viewInflate = LayoutInflater.from(context).inflate(R.layout.view_share_set_button, (ViewGroup) this, false);
        addView(viewInflate);
        int i2 = R.id.shareImage;
        StatefulTintImageView statefulTintImageView = (StatefulTintImageView) AbstractC3375o2.c(R.id.shareImage, viewInflate);
        if (statefulTintImageView != null) {
            i2 = R.id.shareText;
            QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.shareText, viewInflate);
            if (qTextView != null) {
                com.onetrust.otpublishers.headless.databinding.b bVar = new com.onetrust.otpublishers.headless.databinding.b((ConstraintLayout) viewInflate, statefulTintImageView, qTextView, 5);
                Intrinsics.checkNotNullExpressionValue(bVar, "inflate(...)");
                this.q = bVar;
                super.setVisibility(8);
                super.setOnClickListener(new f(18));
                return;
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i2)));
    }
}
