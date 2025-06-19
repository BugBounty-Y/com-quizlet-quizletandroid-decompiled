package androidx.compose.foundation.text.selection;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.collection.AbstractC0216n;
import androidx.collection.C0225x;
import java.util.ArrayList;
import kotlin.NoWhenBranchMatchedException;

/* loaded from: classes.dex */
public final class J {
    public final long a;
    public final long b;
    public final androidx.compose.ui.layout.r c;
    public final boolean d;
    public final C0536q e;
    public final androidx.camera.core.streamsharing.a f;
    public final C0225x g;
    public final ArrayList h;
    public int i;
    public int j;
    public int k;

    public J(long j, long j2, androidx.compose.ui.layout.r rVar, boolean z, C0536q c0536q, androidx.camera.core.streamsharing.a aVar) {
        this.a = j;
        this.b = j2;
        this.c = rVar;
        this.d = z;
        this.e = c0536q;
        this.f = aVar;
        int i = AbstractC0216n.a;
        this.g = new C0225x(6);
        this.h = new ArrayList();
        this.i = -1;
        this.j = -1;
        this.k = -1;
    }

    public final int a(int i, int i2, int i3) {
        if (i == -1) {
            int iK = AbstractC0147y.k(W.x(i2, i3));
            if (iK == 0) {
                return this.k - 1;
            }
            if (iK == 1) {
                return this.k;
            }
            if (iK != 2) {
                throw new NoWhenBranchMatchedException();
            }
        }
        return i;
    }
}
