package com.google.android.gms.internal.ads;

import android.content.Context;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.widget.FrameLayout;
import com.google.android.gms.ads.internal.util.C1633i;
import java.util.ArrayList;

/* renamed from: com.google.android.gms.internal.ads.pk, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2492pk extends FrameLayout {
    public final C1633i a;

    public C2492pk(Context context, View view, C1633i c1633i) {
        super(context);
        setLayoutParams(new FrameLayout.LayoutParams(-1, -1));
        addView(view);
        this.a = c1633i;
    }

    @Override // android.view.ViewGroup
    public final boolean onInterceptTouchEvent(MotionEvent motionEvent) {
        this.a.a(motionEvent);
        return false;
    }

    @Override // android.view.ViewGroup
    public final void removeAllViews() {
        ArrayList arrayList = new ArrayList();
        for (int i = 0; i < getChildCount(); i++) {
            KeyEvent.Callback childAt = getChildAt(i);
            if (childAt != null && (childAt instanceof InterfaceC2529qe)) {
                arrayList.add((InterfaceC2529qe) childAt);
            }
        }
        super.removeAllViews();
        int size = arrayList.size();
        for (int i2 = 0; i2 < size; i2++) {
            ((InterfaceC2529qe) arrayList.get(i2)).destroy();
        }
    }
}
