package androidx.glance.appwidget;

import android.content.Context;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class s0 extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Context b;
    public final /* synthetic */ String c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ s0(Context context, String str, int i) {
        super(0);
        this.a = i;
        this.b = context;
        this.c = str;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return K6.a(this.b, this.c);
            default:
                return P6.d(this.b, this.c);
        }
    }
}
