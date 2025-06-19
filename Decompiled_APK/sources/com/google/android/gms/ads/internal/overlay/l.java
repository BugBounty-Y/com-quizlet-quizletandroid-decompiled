package com.google.android.gms.ads.internal.overlay;

import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageButton;

/* loaded from: classes2.dex */
public final class l extends FrameLayout implements View.OnClickListener {
    public final ImageButton a;
    public final d b;

    /* JADX WARN: Code restructure failed: missing block: B:33:0x0060, code lost:
    
        r0 = null;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public l(android.content.Context r7, com.google.android.gms.ads.internal.overlay.k r8, com.google.android.gms.ads.internal.overlay.d r9) {
        /*
            Method dump skipped, instructions count: 311
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.ads.internal.overlay.l.<init>(android.content.Context, com.google.android.gms.ads.internal.overlay.k, com.google.android.gms.ads.internal.overlay.d):void");
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        d dVar = this.b;
        if (dVar != null) {
            dVar.w = 2;
            dVar.b.finish();
        }
    }
}
