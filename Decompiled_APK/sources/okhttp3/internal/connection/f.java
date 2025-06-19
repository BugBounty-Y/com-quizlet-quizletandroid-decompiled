package okhttp3.internal.connection;

import okio.C5088e;

/* loaded from: classes3.dex */
public final class f extends C5088e {
    public final /* synthetic */ g m;

    public f(g gVar) {
        this.m = gVar;
    }

    @Override // okio.C5088e
    public final void j() {
        this.m.cancel();
    }
}
