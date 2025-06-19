package androidx.glance;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.util.ArrayList;
import kotlin.collections.CollectionsKt;
import kotlin.text.x;

/* loaded from: classes.dex */
public abstract class m implements k {
    public int a;
    public final boolean b;
    public final ArrayList c;

    public m(int i, int i2) {
        i = (i2 & 1) != 0 ? SubsamplingScaleImageView.TILE_SIZE_AUTO : i;
        boolean z = (i2 & 2) == 0;
        this.a = i;
        this.b = z;
        this.c = new ArrayList();
    }

    public final String c() {
        return x.b(CollectionsKt.S(this.c, ",\n", null, null, null, 62));
    }
}
