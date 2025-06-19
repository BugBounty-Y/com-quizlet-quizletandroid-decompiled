package androidx.glance.state;

import android.content.Context;
import androidx.glance.appwidget.s0;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import java.io.File;

/* loaded from: classes.dex */
public final class h implements g {
    public static final h a = new h();

    @Override // androidx.glance.state.g
    public final File a(Context context, String str) {
        return P6.d(context, str);
    }

    @Override // androidx.glance.state.g
    public final Object b(Context context, String str) {
        return androidx.datastore.preferences.core.e.e(null, new s0(context, str, 1), 7);
    }
}
