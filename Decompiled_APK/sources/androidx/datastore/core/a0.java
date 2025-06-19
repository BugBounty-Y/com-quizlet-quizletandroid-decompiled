package androidx.datastore.core;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a0 extends l0 {
    public final Throwable b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a0(Throwable finalException) {
        super(SubsamplingScaleImageView.TILE_SIZE_AUTO);
        Intrinsics.checkNotNullParameter(finalException, "finalException");
        this.b = finalException;
    }
}
