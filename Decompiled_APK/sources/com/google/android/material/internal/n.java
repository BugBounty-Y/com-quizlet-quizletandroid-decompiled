package com.google.android.material.internal;

import android.content.Context;
import android.text.TextPaint;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.ref.WeakReference;

/* loaded from: classes2.dex */
public final class n {
    public float c;
    public float d;
    public final WeakReference f;
    public com.google.android.material.resources.e g;
    public final TextPaint a = new TextPaint(1);
    public final com.google.android.material.chip.b b = new com.google.android.material.chip.b(this, 1);
    public boolean e = true;

    public n(m mVar) {
        this.f = new WeakReference(null);
        this.f = new WeakReference(mVar);
    }

    public final void a(String str) {
        TextPaint textPaint = this.a;
        float fAbs = DefinitionKt.NO_Float_VALUE;
        this.c = str == null ? 0.0f : textPaint.measureText((CharSequence) str, 0, str.length());
        if (str != null) {
            fAbs = Math.abs(textPaint.getFontMetrics().ascent);
        }
        this.d = fAbs;
        this.e = false;
    }

    public final void b(com.google.android.material.resources.e eVar, Context context) {
        if (this.g != eVar) {
            this.g = eVar;
            if (eVar != null) {
                TextPaint textPaint = this.a;
                com.google.android.material.chip.b bVar = this.b;
                eVar.f(context, textPaint, bVar);
                m mVar = (m) this.f.get();
                if (mVar != null) {
                    textPaint.drawableState = mVar.getState();
                }
                eVar.e(context, textPaint, bVar);
                this.e = true;
            }
            m mVar2 = (m) this.f.get();
            if (mVar2 != null) {
                mVar2.a();
                mVar2.onStateChange(mVar2.getState());
            }
        }
    }
}
