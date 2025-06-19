package androidx.camera.core.impl;

import java.util.List;

/* loaded from: classes.dex */
public final class x0 {
    public final q0 a;
    public final A0 b;
    public final C0168g c;
    public final List d;
    public boolean e = false;
    public boolean f = false;

    public x0(q0 q0Var, A0 a0, C0168g c0168g, List list) {
        this.a = q0Var;
        this.b = a0;
        this.c = c0168g;
        this.d = list;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("UseCaseAttachInfo{mSessionConfig=");
        sb.append(this.a);
        sb.append(", mUseCaseConfig=");
        sb.append(this.b);
        sb.append(", mStreamSpec=");
        sb.append(this.c);
        sb.append(", mCaptureTypes=");
        sb.append(this.d);
        sb.append(", mAttached=");
        sb.append(this.e);
        sb.append(", mActive=");
        return android.support.v4.media.session.a.u(sb, this.f, '}');
    }
}
