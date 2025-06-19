package com.quizlet.quizletandroid.ui.activitycenter.views;

import android.content.Context;
import android.text.SpannableString;
import android.text.SpannableStringBuilder;
import android.text.style.ForegroundColorSpan;
import android.text.style.StyleSpan;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import com.braze.ui.contentcards.view.ContentCardViewHolder;
import com.google.android.gms.internal.measurement.AbstractC3058t1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3161h6;
import com.quizlet.partskit.widgets.EllipsizedSubstringTextView;
import com.quizlet.quizletandroid.R;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import kotlin.collections.A;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public final class e extends ContentCardViewHolder {
    public final com.quizlet.qutils.image.loading.a a;
    public final FrameLayout b;
    public final ImageView c;
    public final ImageView d;
    public final EllipsizedSubstringTextView e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(View view, boolean z, com.quizlet.qutils.image.loading.a imageLoader) {
        super(view, z);
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(imageLoader, "imageLoader");
        this.a = imageLoader;
        View viewFindViewById = view.findViewById(R.id.classicCardImageContainer);
        Intrinsics.checkNotNullExpressionValue(viewFindViewById, "findViewById(...)");
        this.b = (FrameLayout) viewFindViewById;
        View viewFindViewById2 = view.findViewById(R.id.classicCardImage);
        Intrinsics.checkNotNullExpressionValue(viewFindViewById2, "findViewById(...)");
        this.c = (ImageView) viewFindViewById2;
        View viewFindViewById3 = view.findViewById(R.id.classicCardSecondaryImage);
        Intrinsics.checkNotNullExpressionValue(viewFindViewById3, "findViewById(...)");
        this.d = (ImageView) viewFindViewById3;
        View viewFindViewById4 = view.findViewById(R.id.classicCardText);
        Intrinsics.checkNotNullExpressionValue(viewFindViewById4, "findViewById(...)");
        this.e = (EllipsizedSubstringTextView) viewFindViewById4;
        this.itemView.setBackgroundResource(z ? R.drawable.activity_center_card_unread_background : R.drawable.activity_center_card_read_background);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void c(long j, String str, String str2) {
        int iMax;
        int i;
        String string;
        String string2;
        long jAbs = Math.abs(System.currentTimeMillis() - TimeUnit.SECONDS.toMillis(j));
        if (jAbs < 3600000) {
            iMax = Math.max((int) (jAbs / 60000), 1);
            i = R.string.activity_center_timestamp_minute_abbr;
        } else if (jAbs < 86400000) {
            iMax = (int) (jAbs / 3600000);
            i = R.string.activity_center_timestamp_hour_abbr;
        } else if (jAbs < 604800000) {
            iMax = (int) (jAbs / 86400000);
            i = R.string.activity_center_timestamp_day_abbr;
        } else {
            iMax = (int) (jAbs / 604800000);
            i = R.string.activity_center_timestamp_week_abbr;
        }
        Object[] args = {Integer.valueOf(iMax)};
        Intrinsics.checkNotNullParameter(args, "args");
        List listP = C4933y.P(args);
        String ellipsizableText = StringsKt.g0(str).toString();
        if (str2 == null || (string = StringsKt.g0(str2).toString()) == null) {
            string = "";
        }
        if (string.length() != 0) {
            String stringToStyle = android.support.v4.media.session.a.l(ellipsizableText, " ", string);
            List<String> substrings = A.b(string);
            Intrinsics.checkNotNullParameter(substrings, "substrings");
            Intrinsics.checkNotNullParameter(stringToStyle, "stringToStyle");
            SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(stringToStyle);
            for (String str3 : substrings) {
                if (StringsKt.G(stringToStyle, str3, false)) {
                    spannableStringBuilder.setSpan(new StyleSpan(1), StringsKt.M(stringToStyle, str3, 0, false, 6), str3.length() + StringsKt.M(stringToStyle, str3, 0, false, 6), 33);
                } else {
                    timber.log.c.a.a(android.support.v4.media.session.a.l(str3, " not part of the whole string ", stringToStyle), new Object[0]);
                }
            }
            ellipsizableText = spannableStringBuilder;
        }
        Context context = this.itemView.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(context, "context");
        if (listP == null || listP.isEmpty()) {
            string2 = context.getString(i);
            Intrinsics.d(string2);
        } else {
            Object[] array = AbstractC3058t1.b(context, listP).toArray(new Object[0]);
            string2 = context.getString(i, Arrays.copyOf(array, array.length));
            Intrinsics.d(string2);
        }
        SpannableString postEllipsisText = new SpannableString(string2.toString());
        Context context2 = this.itemView.getContext();
        Intrinsics.checkNotNullExpressionValue(context2, "getContext(...)");
        Intrinsics.checkNotNullParameter(postEllipsisText, "<this>");
        Intrinsics.checkNotNullParameter(context2, "context");
        int iA = com.quizlet.themes.extensions.a.a(context2, R.attr.textColorSecondary);
        Intrinsics.checkNotNullParameter(postEllipsisText, "<this>");
        AbstractC3161h6.h(postEllipsisText, new ForegroundColorSpan(iA));
        EllipsizedSubstringTextView ellipsizedSubstringTextView = this.e;
        ellipsizedSubstringTextView.getClass();
        Intrinsics.checkNotNullParameter(ellipsizableText, "ellipsizableText");
        Intrinsics.checkNotNullParameter(postEllipsisText, "postEllipsisText");
        ellipsizedSubstringTextView.c = " ";
        ellipsizedSubstringTextView.b = postEllipsisText;
        SpannableStringBuilder spannableStringBuilder2 = ellipsizedSubstringTextView.a;
        spannableStringBuilder2.clear();
        ellipsizedSubstringTextView.setText(spannableStringBuilder2.append((CharSequence) ellipsizableText).append((CharSequence) ellipsizedSubstringTextView.c).append(ellipsizedSubstringTextView.b));
    }
}
