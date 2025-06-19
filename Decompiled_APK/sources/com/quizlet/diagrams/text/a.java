package com.quizlet.diagrams.text;

import android.content.res.Resources;
import android.graphics.Paint;
import android.graphics.Rect;
import android.text.Layout;
import android.text.SpannableStringBuilder;
import android.text.style.ForegroundColorSpan;
import android.view.View;
import android.view.ViewTreeObserver;
import android.widget.TextView;
import androidx.cardview.widget.CardView;
import androidx.compose.animation.d0;
import androidx.recyclerview.widget.RecyclerView;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4615t;
import com.quizlet.quizletandroid.ui.common.dialogs.TextOverlayDialogFragment;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.MatchEndGameFragment;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes2.dex */
public final class a implements ViewTreeObserver.OnGlobalLayoutListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ View c;
    public final /* synthetic */ Object d;

    public /* synthetic */ a(View view, Object obj, int i, int i2) {
        this.a = i2;
        this.c = view;
        this.d = obj;
        this.b = i;
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public final void onGlobalLayout() throws Resources.NotFoundException {
        int i = this.b;
        Object obj = this.d;
        View view = this.c;
        switch (this.a) {
            case 0:
                TextView textView = (TextView) view;
                textView.getViewTreeObserver().removeOnGlobalLayoutListener(this);
                Layout layout = textView.getLayout();
                if (layout != null && layout.getLineCount() > 0 && layout.getEllipsisCount(layout.getLineCount() - 1) > 0) {
                    int dimensionPixelSize = textView.getResources().getDimensionPixelSize(R.dimen.quizlet_edge_margin);
                    StringBuilder sbU = d0.u(textView.getResources().getString(R.string.ellipsis));
                    sbU.append((String) obj);
                    String string = sbU.toString();
                    String strSubstring = textView.getText().toString().substring(textView.getLayout().getLineStart(0), textView.getLayout().getLineEnd(textView.getLineCount() - 1));
                    Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                    while (true) {
                        String strK = android.support.v4.media.session.a.k(strSubstring, string);
                        Rect rect = new Rect();
                        Paint paint = new Paint();
                        paint.setTextSize(textView.getTextSize());
                        paint.getTextBounds(strK, 0, strK.length(), rect);
                        if (((int) Math.ceil(rect.width())) + dimensionPixelSize <= textView.getWidth()) {
                            SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(android.support.v4.media.session.a.k(strSubstring, string));
                            spannableStringBuilder.setSpan(new ForegroundColorSpan(i), strSubstring.length() + 1, (strSubstring + string).length(), 33);
                            textView.setText(spannableStringBuilder);
                            break;
                        } else if (strSubstring.length() == 0) {
                            break;
                        } else {
                            String strSubstring2 = strSubstring.substring(0, strSubstring.length() - 1);
                            Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
                            strSubstring = StringsKt.g0(strSubstring2).toString();
                        }
                    }
                }
                break;
            case 1:
                QTextView qTextView = (QTextView) view;
                if (qTextView.getMeasuredWidth() > 0 && qTextView.getMeasuredHeight() > 0) {
                    qTextView.getViewTreeObserver().removeOnGlobalLayoutListener(this);
                    TextOverlayDialogFragment textOverlayDialogFragment = (TextOverlayDialogFragment) obj;
                    CardView textOverlayContainer = ((C4615t) textOverlayDialogFragment.P()).b;
                    Intrinsics.checkNotNullExpressionValue(textOverlayContainer, "textOverlayContainer");
                    int height = textOverlayContainer.getHeight();
                    int i2 = (i * 2) / 3;
                    if (height > i2) {
                        height = i2;
                    }
                    CardView textOverlayContainer2 = ((C4615t) textOverlayDialogFragment.P()).b;
                    Intrinsics.checkNotNullExpressionValue(textOverlayContainer2, "textOverlayContainer");
                    textOverlayContainer2.getLayoutParams().height = height;
                    CardView textOverlayContainer3 = ((C4615t) textOverlayDialogFragment.P()).b;
                    Intrinsics.checkNotNullExpressionValue(textOverlayContainer3, "textOverlayContainer");
                    textOverlayContainer3.setForegroundGravity(17);
                    break;
                }
                break;
            default:
                RecyclerView recyclerView = (RecyclerView) view;
                if (recyclerView.getMeasuredWidth() > 0 && recyclerView.getMeasuredHeight() > 0) {
                    recyclerView.getViewTreeObserver().removeOnGlobalLayoutListener(this);
                    String str = MatchEndGameFragment.p;
                    ((MatchEndGameFragment) obj).T().n0(i);
                    break;
                }
                break;
        }
    }
}
