package com.quizlet.quizletandroid.ui.activitycenter.views;

import android.content.Context;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.onetrust.otpublishers.headless.UI.fragment.q;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.o0;
import com.quizlet.quizletandroid.k;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class UnreadBadgeView extends c {
    public final o0 q;
    public final k r;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public UnreadBadgeView(@NotNull Context context) {
        this(context, null, 14);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    @Override // com.quizlet.quizletandroid.ui.activitycenter.views.c
    public void setBadgeBackground(int i) {
        this.r.s(i);
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public UnreadBadgeView(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 12);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public UnreadBadgeView(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet);
        View viewInflate = LayoutInflater.from(context).inflate(R.layout.view_unread_badge, (ViewGroup) this, false);
        addView(viewInflate);
        int i2 = R.id.count;
        QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.count, viewInflate);
        if (qTextView != null) {
            i2 = R.id.dot;
            View viewC = AbstractC3375o2.c(R.id.dot, viewInflate);
            if (viewC != null) {
                o0 o0Var = new o0((ConstraintLayout) viewInflate, qTextView, viewC, 0);
                Intrinsics.checkNotNullExpressionValue(o0Var, "inflate(...)");
                this.q = o0Var;
                k kVar = new k(context, new h(new g(R.drawable.unread_badge, R.dimen.activity_center_unread_badge_count_size, R.dimen.activity_center_unread_badge_count_nine_plus_width), new q(this, 28)));
                this.r = kVar;
                if (attributeSet != null) {
                    kVar.o(context, attributeSet);
                    return;
                }
                return;
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i2)));
    }
}
