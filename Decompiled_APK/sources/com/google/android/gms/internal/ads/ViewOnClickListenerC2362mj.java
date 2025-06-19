package com.google.android.gms.internal.ads;

import android.view.View;
import java.lang.ref.WeakReference;
import java.util.HashMap;

/* renamed from: com.google.android.gms.internal.ads.mj, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class ViewOnClickListenerC2362mj implements View.OnClickListener {
    public final C1843ak a;
    public final com.google.android.gms.common.util.a b;
    public V8 c;
    public C2217j9 d;
    public String e;
    public Long f;
    public WeakReference g;

    public ViewOnClickListenerC2362mj(C1843ak c1843ak, com.google.android.gms.common.util.a aVar) {
        this.a = c1843ak;
        this.b = aVar;
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        View view2;
        WeakReference weakReference = this.g;
        if (weakReference == null || weakReference.get() != view) {
            return;
        }
        if (this.e != null && this.f != null) {
            HashMap map = new HashMap();
            map.put("id", this.e);
            map.put("time_interval", String.valueOf(this.b.currentTimeMillis() - this.f.longValue()));
            map.put("messageType", "onePointFiveClick");
            this.a.b(map);
        }
        this.e = null;
        this.f = null;
        WeakReference weakReference2 = this.g;
        if (weakReference2 == null || (view2 = (View) weakReference2.get()) == null) {
            return;
        }
        view2.setClickable(false);
        view2.setOnClickListener(null);
        this.g = null;
    }
}
