package retrofit2.converter.scalars;

import androidx.transition.C1412o;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import java.util.regex.Pattern;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.w;
import retrofit2.InterfaceC5186k;

/* loaded from: classes3.dex */
public final class a implements InterfaceC5186k {
    public static final a a = new a();
    public static final w b;

    static {
        Pattern pattern = w.e;
        b = AbstractC3347h2.c("text/plain; charset=UTF-8");
    }

    @Override // retrofit2.InterfaceC5186k
    public final Object convert(Object obj) {
        String content = String.valueOf(obj);
        Intrinsics.checkNotNullParameter(content, "content");
        return C1412o.f(content, b);
    }
}
