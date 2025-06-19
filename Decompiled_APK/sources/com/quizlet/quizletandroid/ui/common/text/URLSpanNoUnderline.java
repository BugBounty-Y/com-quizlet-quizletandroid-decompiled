package com.quizlet.quizletandroid.ui.common.text;

import android.app.Activity;
import android.content.Context;
import android.content.ContextWrapper;
import android.os.Parcelable;
import android.text.TextPaint;
import android.text.style.URLSpan;
import android.view.View;
import com.onetrust.otpublishers.headless.UI.DataModels.f;
import com.quizlet.quizletandroid.ui.webpages.a;

/* loaded from: classes3.dex */
public class URLSpanNoUnderline extends URLSpan {
    public static final Parcelable.Creator<URLSpanNoUnderline> CREATOR = new f(13);
    public String a;

    @Override // android.text.style.URLSpan, android.text.style.ClickableSpan
    public final void onClick(View view) {
        Activity activity;
        Context context = view.getContext();
        while (true) {
            if (!(context instanceof ContextWrapper)) {
                activity = null;
                break;
            } else {
                if (context instanceof Activity) {
                    activity = (Activity) context;
                    break;
                }
                context = ((ContextWrapper) context).getBaseContext();
            }
        }
        if (activity != null) {
            a.a.b(activity, getURL(), this.a);
        } else {
            super.onClick(view);
        }
    }

    @Override // android.text.style.ClickableSpan, android.text.style.CharacterStyle
    public final void updateDrawState(TextPaint textPaint) {
        textPaint.setUnderlineText(false);
    }
}
