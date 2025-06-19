package androidx.camera.core.impl;

import android.util.Range;
import android.util.Size;
import androidx.camera.core.C0196t;

/* renamed from: androidx.camera.core.impl.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0168g {
    public static final Range f = new Range(0, 0);
    public final Size a;
    public final C0196t b;
    public final Range c;
    public final androidx.camera.camera2.impl.b d;
    public final boolean e;

    public C0168g(Size size, C0196t c0196t, Range range, androidx.camera.camera2.impl.b bVar, boolean z) {
        this.a = size;
        this.b = c0196t;
        this.c = range;
        this.d = bVar;
        this.e = z;
    }

    public final com.quizlet.data.interactor.folderwithcreator.m a() {
        com.quizlet.data.interactor.folderwithcreator.m mVar = new com.quizlet.data.interactor.folderwithcreator.m();
        mVar.a = this.a;
        mVar.b = this.b;
        mVar.c = this.c;
        mVar.d = this.d;
        mVar.e = Boolean.valueOf(this.e);
        return mVar;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof C0168g)) {
            return false;
        }
        C0168g c0168g = (C0168g) obj;
        if (!this.a.equals(c0168g.a) || !this.b.equals(c0168g.b) || !this.c.equals(c0168g.c)) {
            return false;
        }
        androidx.camera.camera2.impl.b bVar = c0168g.d;
        androidx.camera.camera2.impl.b bVar2 = this.d;
        if (bVar2 == null) {
            if (bVar != null) {
                return false;
            }
        } else if (!bVar2.equals(bVar)) {
            return false;
        }
        return this.e == c0168g.e;
    }

    public final int hashCode() {
        int iHashCode = (((((this.a.hashCode() ^ 1000003) * 1000003) ^ this.b.hashCode()) * 1000003) ^ this.c.hashCode()) * 1000003;
        androidx.camera.camera2.impl.b bVar = this.d;
        return ((iHashCode ^ (bVar == null ? 0 : bVar.hashCode())) * 1000003) ^ (this.e ? 1231 : 1237);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StreamSpec{resolution=");
        sb.append(this.a);
        sb.append(", dynamicRange=");
        sb.append(this.b);
        sb.append(", expectedFrameRateRange=");
        sb.append(this.c);
        sb.append(", implementationOptions=");
        sb.append(this.d);
        sb.append(", zslDisabled=");
        return android.support.v4.media.session.a.o("}", sb, this.e);
    }
}
