package com.pubmatic.sdk.webrendering.ui;

import android.content.Context;
import android.content.res.Resources;
import android.os.Looper;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public class e extends FrameLayout {
    private com.pubmatic.sdk.common.utility.d a;

    @NonNull
    private TextView b;
    private boolean c;
    private int d;

    @NonNull
    private final Resources e;
    private d f;

    public class a extends com.pubmatic.sdk.common.utility.d {
        public a(long j, long j2, Looper looper) {
            super(j, j2, looper);
        }

        @Override // com.pubmatic.sdk.common.utility.d
        public void onFinish() {
            if (e.this.f != null) {
                e.this.f.onTimerExhausted();
            }
        }

        @Override // com.pubmatic.sdk.common.utility.d
        public void onTick(long j) {
            e.this.setTimeToTimerTextView(j);
        }
    }

    private e(@NonNull Context context) {
        super(context);
        this.c = false;
        this.e = context.getResources();
        TextView textViewB = b();
        this.b = textViewB;
        addView(textViewB);
    }

    @NonNull
    private TextView b() {
        this.b = com.pubmatic.sdk.webrendering.a.createSkipDurationTextView(getContext(), com.pubmatic.sdk.webrendering.e.pob_skip_duration_timer);
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(this.e.getDimensionPixelOffset(com.pubmatic.sdk.webrendering.c.pob_control_width), this.e.getDimensionPixelOffset(com.pubmatic.sdk.webrendering.c.pob_control_height));
        layoutParams.gravity = 17;
        this.b.setLayoutParams(layoutParams);
        return this.b;
    }

    private void c() {
        com.pubmatic.sdk.common.utility.d dVar = this.a;
        if (dVar != null) {
            dVar.pause();
        }
    }

    private void d() {
        com.pubmatic.sdk.common.utility.d dVar = this.a;
        if (dVar != null) {
            dVar.resume();
        }
    }

    private void e() {
        if (this.a == null) {
            a aVar = new a(this.d, 1L, Looper.getMainLooper());
            this.a = aVar;
            aVar.start();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setTimeToTimerTextView(long j) {
        this.b.setText(String.valueOf(j));
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        if (this.c && hasWindowFocus()) {
            e();
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        if (this.c) {
            a();
        }
    }

    @Override // android.view.View
    public void onWindowFocusChanged(boolean z) {
        super.onWindowFocusChanged(z);
        if (this.c) {
            if (!z) {
                c();
            } else {
                e();
                d();
            }
        }
    }

    public void setTimerExhaustedListener(d dVar) {
        this.f = dVar;
    }

    private void a() {
        com.pubmatic.sdk.common.utility.d dVar = this.a;
        if (dVar != null) {
            dVar.cancel();
        }
    }

    public e(@NonNull Context context, int i) {
        this(context);
        if (i > 0) {
            this.d = i;
            this.c = true;
        }
        setLayoutParams(com.pubmatic.sdk.webrendering.a.getLayoutParamsForTopRightPosition(context));
        setTimeToTimerTextView(i);
    }
}
