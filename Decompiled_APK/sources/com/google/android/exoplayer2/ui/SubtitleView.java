package com.google.android.exoplayer2.ui;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.view.accessibility.CaptioningManager;
import android.widget.FrameLayout;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/* loaded from: classes2.dex */
public final class SubtitleView extends FrameLayout {
    public List a;
    public c b;
    public float c;
    public float d;
    public boolean e;
    public boolean f;
    public int g;
    public f h;
    public View i;

    public SubtitleView(Context context) {
        this(context, null);
    }

    private List<Object> getCuesWithStylingPreferencesApplied() {
        if (this.e && this.f) {
            return this.a;
        }
        ArrayList arrayList = new ArrayList(this.a.size());
        if (this.a.size() <= 0) {
            return arrayList;
        }
        this.a.get(0).getClass();
        throw new ClassCastException();
    }

    private float getUserCaptionFontScale() {
        CaptioningManager captioningManager;
        if (com.google.android.exoplayer2.util.a.a < 19 || isInEditMode() || (captioningManager = (CaptioningManager) getContext().getSystemService("captioning")) == null || !captioningManager.isEnabled()) {
            return 1.0f;
        }
        return captioningManager.getFontScale();
    }

    private c getUserCaptionStyle() {
        CaptioningManager captioningManager;
        int i = com.google.android.exoplayer2.util.a.a;
        c cVar = c.e;
        if (i < 19 || isInEditMode() || (captioningManager = (CaptioningManager) getContext().getSystemService("captioning")) == null || !captioningManager.isEnabled()) {
            return cVar;
        }
        CaptioningManager.CaptionStyle userStyle = captioningManager.getUserStyle();
        if (i >= 21) {
            return new c(userStyle.hasForegroundColor() ? userStyle.foregroundColor : -1, userStyle.hasBackgroundColor() ? userStyle.backgroundColor : -16777216, userStyle.hasWindowColor() ? userStyle.windowColor : 0, userStyle.hasEdgeType() ? userStyle.edgeType : 0, userStyle.hasEdgeColor() ? userStyle.edgeColor : -1, userStyle.getTypeface());
        }
        return new c(userStyle.foregroundColor, userStyle.backgroundColor, 0, userStyle.edgeType, userStyle.edgeColor, userStyle.getTypeface());
    }

    private <T extends View & f> void setView(T t) {
        removeView(this.i);
        View view = this.i;
        if (view instanceof h) {
            ((h) view).b.destroy();
        }
        this.i = t;
        this.h = t;
        addView(t);
    }

    public final void a() {
        this.h.a(getCuesWithStylingPreferencesApplied(), this.b, this.c, this.d);
    }

    public void setApplyEmbeddedFontSizes(boolean z) {
        this.f = z;
        a();
    }

    public void setApplyEmbeddedStyles(boolean z) {
        this.e = z;
        a();
    }

    public void setBottomPaddingFraction(float f) {
        this.d = f;
        a();
    }

    public void setCues(List<Object> list) {
        if (list == null) {
            list = Collections.EMPTY_LIST;
        }
        this.a = list;
        a();
    }

    public void setFractionalTextSize(float f) {
        this.c = f;
        a();
    }

    public void setStyle(c cVar) {
        this.b = cVar;
        a();
    }

    public void setViewType(int i) {
        if (this.g == i) {
            return;
        }
        if (i == 1) {
            setView(new b(getContext()));
        } else {
            if (i != 2) {
                throw new IllegalArgumentException();
            }
            setView(new h(getContext()));
        }
        this.g = i;
    }

    public SubtitleView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.a = Collections.EMPTY_LIST;
        this.b = c.e;
        this.c = 0.0533f;
        this.d = 0.08f;
        this.e = true;
        this.f = true;
        b bVar = new b(context);
        this.h = bVar;
        this.i = bVar;
        addView(bVar);
        this.g = 1;
    }
}
