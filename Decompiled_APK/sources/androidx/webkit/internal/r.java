package androidx.webkit.internal;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3379p2;

/* loaded from: classes.dex */
public final class r extends b {
    @Override // androidx.webkit.internal.c
    public final boolean b() {
        if (!super.b() || !AbstractC3379p2.c("MULTI_PROCESS")) {
            return false;
        }
        int i = androidx.webkit.i.a;
        if (s.b.b()) {
            return u.a.getStatics().isMultiProcessEnabled();
        }
        throw s.a();
    }
}
