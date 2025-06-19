package io.ktor.client.plugins;

import com.google.android.gms.internal.mlkit_vision_barcode.s7;
import java.nio.charset.Charset;
import java.util.Comparator;
import kotlin.Pair;

/* loaded from: classes3.dex */
public final class B implements Comparator {
    public final /* synthetic */ int a;

    public /* synthetic */ B(int i) {
        this.a = i;
    }

    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                return kotlin.comparisons.a.b(s7.d((Charset) obj), s7.d((Charset) obj2));
            default:
                return kotlin.comparisons.a.b((Float) ((Pair) obj2).b, (Float) ((Pair) obj).b);
        }
    }
}
