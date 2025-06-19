package androidx.glance.text;

import androidx.glance.k;
import androidx.glance.n;
import androidx.glance.p;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;

/* loaded from: classes.dex */
public final class a implements k {
    public g b;
    public String a = "";
    public int c = SubsamplingScaleImageView.TILE_SIZE_AUTO;
    public p d = n.a;

    @Override // androidx.glance.k
    public final p a() {
        return this.d;
    }

    @Override // androidx.glance.k
    public final void b(p pVar) {
        this.d = pVar;
    }

    @Override // androidx.glance.k
    public final k copy() {
        a aVar = new a();
        aVar.d = this.d;
        aVar.a = this.a;
        aVar.b = this.b;
        aVar.c = this.c;
        return aVar;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("EmittableText(");
        sb.append(this.a);
        sb.append(", style=");
        sb.append(this.b);
        sb.append(", modifier=");
        sb.append(this.d);
        sb.append(", maxLines=");
        return android.support.v4.media.session.a.q(sb, this.c, ')');
    }
}
