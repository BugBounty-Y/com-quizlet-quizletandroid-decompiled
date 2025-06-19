package com.google.android.gms.ads.internal.overlay;

import android.content.Context;
import android.view.MotionEvent;
import android.widget.RelativeLayout;
import com.google.android.gms.ads.internal.util.C1633i;

/* loaded from: classes2.dex */
public final class f extends RelativeLayout {
    public final C1633i a;
    public boolean b;

    public f(Context context, String str, String str2, String str3) {
        super(context);
        C1633i c1633i = new C1633i(context);
        c1633i.c = str;
        this.a = c1633i;
        c1633i.e = str2;
        c1633i.d = str3;
    }

    @Override // android.view.ViewGroup
    public final boolean onInterceptTouchEvent(MotionEvent motionEvent) {
        if (this.b) {
            return false;
        }
        this.a.a(motionEvent);
        return false;
    }
}
