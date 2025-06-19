package org.wordpress.aztec.watchers.event.sequence.known.space.steps;

import android.text.Editable;
import android.text.SpannableStringBuilder;
import com.google.android.gms.internal.mlkit_vision_camera.Y2;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.watchers.event.text.e;

/* loaded from: classes3.dex */
public final class c extends e {
    public SpannableStringBuilder e;
    public int f;
    public int g;

    @Override // org.wordpress.aztec.watchers.event.text.e
    public final boolean a() {
        org.wordpress.aztec.watchers.event.text.b bVar = this.a;
        this.e = bVar.a;
        if (bVar.c != 0 || bVar.d <= 0) {
            return false;
        }
        org.wordpress.aztec.watchers.event.text.c cVar = this.b;
        if (cVar.b < 0 || cVar.d <= 0) {
            return false;
        }
        SpannableStringBuilder spannableStringBuilder = cVar.a;
        Intrinsics.d(spannableStringBuilder);
        if (spannableStringBuilder.length() <= 0) {
            return false;
        }
        org.wordpress.aztec.watchers.event.text.a aVar = this.c;
        SpannableStringBuilder spannableStringBuilder2 = this.e;
        Intrinsics.d(spannableStringBuilder2);
        int iE = Y2.e(spannableStringBuilder2);
        Editable editable = aVar.a;
        Intrinsics.d(editable);
        return iE < Y2.e(editable);
    }
}
