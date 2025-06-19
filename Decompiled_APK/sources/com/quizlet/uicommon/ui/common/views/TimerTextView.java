package com.quizlet.uicommon.ui.common.views;

import android.content.Context;
import android.os.Handler;
import android.util.AttributeSet;
import com.google.android.gms.common.api.internal.w;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.text.DecimalFormat;

/* loaded from: classes3.dex */
public class TimerTextView extends QTextView {
    public final Handler a;
    public long b;
    public long c;
    public long d;
    public int e;
    public final DecimalFormat f;
    public final w g;

    public TimerTextView(Context context) {
        super(context);
        this.a = new Handler();
        this.c = 0L;
        this.e = R.string.number_with_seconds;
        this.f = new DecimalFormat("0.0");
        this.g = new w(this, 19);
        this.b = System.currentTimeMillis();
    }

    public long getBase() {
        return this.b;
    }

    public long getElapsedTime() {
        return this.d;
    }

    public long getTimeModifier() {
        return this.c;
    }

    public void setBase(long j) {
        this.b = j;
    }

    public void setTimeModifier(long j) {
        this.c = j;
    }

    public void setTimerFormat(boolean z) {
        this.e = z ? R.string.number_without_seconds : this.e;
        setText(getResources().getString(this.e, this.f.format(DefinitionKt.NO_Float_VALUE / 1000.0d)));
    }

    public TimerTextView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.a = new Handler();
        this.c = 0L;
        this.e = R.string.number_with_seconds;
        this.f = new DecimalFormat("0.0");
        this.g = new w(this, 19);
        this.b = System.currentTimeMillis();
    }
}
