package com.quizlet.quizletandroid.ui.common.views;

import android.content.Context;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.quizlet.quizletandroid.R;

/* loaded from: classes3.dex */
public class LoadingIndicatorView extends LinearLayout {
    public final TextView a;

    public LoadingIndicatorView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.a = (TextView) LayoutInflater.from(context).inflate(R.layout.loading_indicator, this).findViewById(R.id.loading_text);
    }

    public void setLoadingText(String str) {
        this.a.setText(str);
    }
}
