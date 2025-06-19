package com.facebook.internal;

import android.content.Context;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.webkit.WebView;

/* loaded from: classes.dex */
public final class Q extends WebView {
    public final /* synthetic */ int a = 0;

    public /* synthetic */ Q(Context context) {
        super(context);
    }

    @Override // android.webkit.WebView, android.view.View
    public boolean onTouchEvent(MotionEvent motionEvent) {
        switch (this.a) {
            case 1:
                super.onTouchEvent(motionEvent);
                return false;
            default:
                return super.onTouchEvent(motionEvent);
        }
    }

    @Override // android.webkit.WebView, android.view.View
    public void onWindowFocusChanged(boolean z) {
        switch (this.a) {
            case 0:
                try {
                    super.onWindowFocusChanged(z);
                    break;
                } catch (NullPointerException unused) {
                    return;
                }
            default:
                super.onWindowFocusChanged(z);
                break;
        }
    }

    @Override // android.view.View
    public boolean performClick() {
        switch (this.a) {
            case 1:
                super.performClick();
                return false;
            default:
                return super.performClick();
        }
    }

    public /* synthetic */ Q(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
    }
}
