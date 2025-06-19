package leakcanary.internal;

import android.os.Handler;
import android.os.Looper;
import androidx.fragment.app.I;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class a extends r implements Function0 {
    public static final a b = new a(0, 0);
    public static final a c = new a(0, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ a(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        boolean z;
        switch (this.a) {
            case 0:
                try {
                    int i = I.a;
                    z = true;
                } catch (Throwable unused) {
                    z = false;
                }
                return Boolean.valueOf(z);
            default:
                return new Handler(Looper.getMainLooper());
        }
    }
}
